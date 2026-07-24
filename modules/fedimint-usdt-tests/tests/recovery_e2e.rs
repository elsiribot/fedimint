//! **Phase 9 seed-recovery acceptance test.** Proves that a deposit allocated
//! by one client (whose deposit claim keys are now deterministically derived
//! from the module root secret and a persisted per-deposit index -- see
//! [`fedimint_usdt_client::UsdtClientModule::allocate_deposit`]) is fully
//! recoverable from the seed ALONE, without any of the first client's DB
//! state.
//!
//! DB-loss is simulated faithfully by building a SECOND, independent client
//! with a FRESH (empty) database but the SAME root secret as the first. The
//! second client therefore starts with no `ClaimKey`/`NextDepositIndex`
//! entries at all -- exactly the "client DB lost before claiming" scenario
//! issue #5 is about. It then runs
//! [`fedimint_usdt_client::UsdtClientModule::recover_deposits`], which rescans
//! the federation by re-deriving each seed-indexed claim key, and asserts the
//! deposit account + claimable balance are rediscovered and (via the existing
//! `claim` path) actually claimable into `USDT_UNIT` e-cash.
//!
//! A shared [`MockEvmRpc`] stands in for the EVM chain (mirroring `tests.rs`),
//! so no anvil is required. Slow (real 4-guardian consensus + deposit-checker
//! ticks); intentionally run in the foreground.

mod common;

use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
use common::MockEvmRpc;
use fedimint_client::{ClientHandleArc, RootSecret};
use fedimint_client_module::secret::{PlainRootSecretStrategy, RootSecretStrategy};
use fedimint_core::Amount;
use fedimint_core::db::Database;
use fedimint_core::db::mem_impl::MemDatabase;
use fedimint_core::runtime::{Instant, sleep};
use fedimint_mintv2_client::MintClientInit as Mintv2ClientInit;
use fedimint_mintv2_common::KIND as MINTV2_KIND;
use fedimint_mintv2_common::config::MintGenParams;
use fedimint_mintv2_server::MintInit as Mintv2Init;
use fedimint_testing::fixtures::Fixtures;
use fedimint_usdt_client::api::UsdtFederationApi;
use fedimint_usdt_client::{UsdtClientInit, UsdtClientModule};
use fedimint_usdt_common::{EvmAddress, USDT_UNIT, UsdtAmount};
use fedimint_usdt_server::UsdtInit;

/// A federation with two mintv2 instances (Bitcoin-denominated primary plus a
/// second `USDT_UNIT`-denominated instance the usdt claim path mints into) and
/// the usdt module wired to `mock` as every guardian's EVM RPC. Mirrors
/// `tests.rs::dual_mint_fixtures`, replicated here since that helper is
/// file-local to `tests.rs`.
fn dual_mint_fixtures(mock: Arc<MockEvmRpc>) -> Fixtures {
    Fixtures::new_primary(Mintv2ClientInit, Mintv2Init)
        .with_extra_module_instance(
            MINTV2_KIND,
            MintGenParams {
                amount_unit: USDT_UNIT,
            },
        )
        .with_module(UsdtClientInit, UsdtInit::with_evm_rpc(mock))
}

/// Builds a client joined to `fed` with an explicit, caller-supplied
/// `root_secret` and a fresh empty [`MemDatabase`]. Two calls with the SAME
/// `root_secret` derive identical deposit claim keys (see
/// [`UsdtClientModule::allocate_deposit`]); the second call's empty DB models
/// a client whose local state was lost.
async fn join_with_root_secret(
    fed: &fedimint_testing::federation::FederationTest,
    root_secret: RootSecret,
) -> ClientHandleArc {
    let db: Database = MemDatabase::new().into();
    fed.join_client_with_db(db, root_secret).await
}

#[tokio::test(flavor = "multi_thread")]
async fn deposit_is_recoverable_from_seed_after_db_loss() -> anyhow::Result<()> {
    let mock = Arc::new(MockEvmRpc::new());
    // The usdt module's default `UsdtGenParams::usdt_contract` placeholder.
    let usdt_contract = EvmAddress([0u8; 20]);
    mock.set_chain_id(31337);
    mock.set_block_number(100);

    let fed = dual_mint_fixtures(mock.clone())
        .new_fed_builder(0)
        .disable_mint_fees()
        .build()
        .await;

    // The shared seed both clients are derived from. A 64-byte client secret
    // deterministically maps to a `RootSecret` exactly as
    // `FederationTest::new_client_with` does it; here we hold onto it so a
    // second client can be built from the same seed.
    let client_secret: [u8; 64] = [7u8; 64];
    let root_secret =
        RootSecret::StandardDoubleDerive(PlainRootSecretStrategy::to_root_secret(&client_secret));

    // --- Client 1: allocate + fund + get the deposit credited. ---
    let client1 = join_with_root_secret(&fed, root_secret.clone()).await;
    let usdt1 = client1.get_first_module::<UsdtClientModule>()?;

    // Part C: drive the module to Ready before allocating a deposit (the
    // client gates `allocate_deposit` on the readiness state machine).
    let group_public_key = client1
        .api()
        .with_module(usdt1.id)
        .group_public_key()
        .await?;
    common::mock_ready_stack(
        &mock,
        &group_public_key,
        usdt1.config().entry_point,
        usdt1.config().account_factory,
        usdt1.config().simple_account_impl,
    );
    common::await_usdt_ready(&usdt1, Duration::from_secs(60)).await?;

    // Wait for a `FeeVote` median to exist before relying on it below.
    // `MockEvmRpc`'s default `FeeVote` is now sane and nonzero (see
    // `common::mock::State::default`), but the guardians' 1s poller ticks +
    // consensus still need real wall-clock time to converge on a median after
    // boot, and `deposit_fee_quote` returns an `Err` (not a placeholder `Ok`)
    // until one exists (security finding 06's client-confusion facet) -- so
    // this retries PAST the `Err`, not just past an `Ok` with a zero fee.
    // `process_input` would otherwise reject a claim with
    // `DepositFeeInsufficient` before any median exists, mirroring how the
    // withdrawal e2e tests wait for `withdraw_fee_quote` to converge first.
    let fee_deadline = Instant::now() + Duration::from_secs(30);
    let deposit_fee = loop {
        if let Ok(quote) = usdt1.deposit_fee_quote().await
            && quote.fee.0 > 0
        {
            break quote.fee;
        }
        if Instant::now() >= fee_deadline {
            bail!("deposit_fee_quote never converged to a nonzero quote before the deadline");
        }
        sleep(Duration::from_millis(300)).await;
    };

    let (claim_keypair, account) = usdt1.allocate_deposit().await?;

    // The claim mints the NET `net_deposit_amount` (a multiple of 512 msat --
    // mintv2's smallest client denomination -- so it's exactly representable
    // as e-cash with no rounding dust); the on-chain deposit must therefore
    // fund `net_deposit_amount + deposit_fee` (the fee is deducted at claim
    // time -- Task 3/4 of the deposit-fee plan).
    let net_deposit_amount = UsdtAmount(2_560_000);
    let deposit_amount = UsdtAmount(net_deposit_amount.0 + deposit_fee.0);
    mock.set_erc20_balance_at(usdt_contract, account, 10, deposit_amount);
    usdt1.check_deposit(claim_keypair.public_key()).await?;

    let credited_deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let status = usdt1.deposit_status(claim_keypair.public_key()).await?;
        if status.credited == deposit_amount {
            break;
        }
        if Instant::now() >= credited_deadline {
            bail!("deposit was never credited before the deadline (last status: {status:?})");
        }
        sleep(Duration::from_millis(300)).await;
    }

    // --- Client 2: SAME seed, FRESH empty DB (simulating total client-DB
    //     loss). It has no ClaimKey/NextDepositIndex entries at all. ---
    let client2 = join_with_root_secret(&fed, root_secret.clone()).await;
    let usdt2 = client2.get_first_module::<UsdtClientModule>()?;

    // Recover from the seed alone.
    let summary = usdt2.recover_deposits(20).await?;

    // The single credited deposit is rediscovered, at index 0, with the same
    // account, claim key, and claimable balance.
    assert_eq!(
        summary.recovered, 1,
        "exactly one credited deposit must be rediscovered (summary: {summary:?})"
    );
    assert_eq!(summary.total_credited, deposit_amount);
    assert_eq!(summary.total_claimable, deposit_amount);
    let recovered = &summary.accounts[0];
    assert_eq!(recovered.index, 0);
    assert_eq!(recovered.account, account);
    assert_eq!(recovered.claim_pk, claim_keypair.public_key());
    assert_eq!(recovered.claimable, deposit_amount);

    // Recovery re-stored the claim key, so the existing single-shot `claim`
    // path works on the second client with only the recovered public key.
    // `claim` returns both the gross claimed amount and the deposit fee
    // actually charged against it (Task 5 cleanup: threading the real charged
    // fee through `ClaimResult` rather than a separately re-fetched quote).
    // No fee cap under test here (security finding 07 client-side caps) --
    // `accept_high_fee: true` preserves this test's prior unrestricted-quote
    // behavior.
    let result = usdt2.claim(recovered.claim_pk, None, true).await?;
    assert_eq!(result.claimed, deposit_amount);
    assert_eq!(result.fee, deposit_fee);

    // The claimed USDT e-cash (net of the deposit fee) lands in the second
    // client's `USDT_UNIT` balance. Issuance is asynchronous even after the
    // claim tx is accepted, so poll with a timeout.
    let poll_deadline = Instant::now() + Duration::from_secs(30);
    let balance = loop {
        let balance = client2.get_balance_for_unit(USDT_UNIT).await?;
        if balance == Amount::from_msats(net_deposit_amount.0) || Instant::now() >= poll_deadline {
            break balance;
        }
        sleep(Duration::from_millis(200)).await;
    };
    assert_eq!(
        balance,
        Amount::from_msats(net_deposit_amount.0),
        "the recovered deposit must be claimable into USDT_UNIT e-cash (minus the deposit fee) \
         on the seed-only client"
    );

    // A subsequent `allocate_deposit` on the recovered client must not collide
    // with the recovered index 0: `recover_deposits` advanced
    // `NextDepositIndex` past it, so the next deposit uses index 1 (a distinct
    // account).
    // The federation is already `Ready` (same shared mock/consensus DB as
    // client 1), so this returns immediately; kept for robustness.
    common::await_usdt_ready(&usdt2, Duration::from_secs(60)).await?;
    let (_next_keypair, next_account) = usdt2.allocate_deposit().await?;
    assert_ne!(
        next_account, account,
        "a post-recovery allocate_deposit must not reuse the recovered account"
    );

    Ok(())
}
