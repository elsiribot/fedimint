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
//! entries at all -- exactly the "client DB lost before crediting" scenario
//! issue #5 is about.
//!
//! Crediting is now proof-driven (deposit-by-proof, Task 9): a deposit is
//! credited AND minted in one no-fee transaction only when someone submits an
//! on-chain balance proof, so there is no "credited-but-unclaimed" state a
//! second client could re-claim. This test therefore models the recovery of a
//! deposit that was FUNDED on-chain but never credited before the DB was lost:
//! the seed-only client runs
//! [`fedimint_usdt_client::UsdtClientModule::recover_deposits`] with
//! `check_uncredited` (security finding 08), which rediscovers the
//! funded-but-uncredited deposit and re-persists its claim key, then CREDITS +
//! MINTS it itself via the client proof path -- proving the deposit is fully
//! recoverable AND spendable from the seed alone. A follow-up `recover` then
//! sees it credited and advances the deposit index so it is never reused.
//!
//! A shared [`MockEvmRpc`] stands in for the EVM chain (mirroring `tests.rs`),
//! so no anvil is required. Slow (real 4-guardian consensus); intentionally
//! run in the foreground.

mod common;

use std::sync::Arc;
use std::time::Duration;

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
    // Script the fee estimate explicitly so the deposit fee the proof path
    // charges is a deterministic value this test can compute the expected
    // net-minted balance from.
    let scripted_fee = fedimint_usdt_common::FeeVote {
        max_fee_per_gas_wei: 100_000_000,
        usdt_per_eth_e6: 3_000_000_000,
    };
    mock.set_fee_estimate(scripted_fee);
    let deposit_fee = fedimint_usdt_common::deposit_fee_quote(&scripted_fee)
        .expect("scripted fee must produce a quote");

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

    // --- Client 1: the original depositor. Allocates deposit index 0 and
    //     funds it on-chain, then "loses" its DB BEFORE ever crediting the
    //     deposit (crediting is now proof-driven -- see below). ---
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

    let (claim_keypair, account) = usdt1.allocate_deposit().await?;

    // Deposit-by-proof credits the full proven balance and mints it net of
    // the deposit fee in one transaction, so the deposit is chosen as a
    // 512-msat-multiple NET (mintv2's smallest client denomination, exactly
    // representable as e-cash with no rounding dust) padded by the
    // deterministic fee. Client 1 deliberately does NOT submit a proof -- it
    // models a depositor who funded the account on-chain but lost its DB
    // BEFORE crediting.
    let net_amount = UsdtAmount(2_560_000);
    let deposit_amount = UsdtAmount(net_amount.0 + deposit_fee.0);

    // --- Client 2: SAME seed, FRESH empty DB (simulating total client-DB
    //     loss). It has no ClaimKey/NextDepositIndex entries at all. ---
    let client2 = join_with_root_secret(&fed, root_secret.clone()).await;
    let usdt2 = client2.get_first_module::<UsdtClientModule>()?;

    // Recover from the seed alone. The deposit is funded-but-UNCREDITED, so it
    // is rediscovered via the security-finding-08 `check_uncredited` path
    // (`checked`, not `accounts`): nothing is credited yet, but its claim key
    // is re-persisted so the seed-only client can credit it next.
    let summary = usdt2.recover_deposits(20, true).await?;
    assert_eq!(
        summary.recovered, 0,
        "nothing is credited yet, so no already-credited account is recovered (summary: \
         {summary:?})"
    );
    assert_eq!(summary.total_credited, UsdtAmount(0));
    assert_eq!(summary.total_claimable, UsdtAmount(0));
    // With nothing credited, the gap-limited scan reports EVERY scanned index as
    // `checked` (all report `credited == 0`); the one that matters is index 0,
    // whose re-persisted claim key + account must match the original allocation.
    let checked = summary
        .checked
        .iter()
        .find(|c| c.index == 0)
        .unwrap_or_else(|| {
            panic!("index 0 must be rediscovered via check_uncredited: {summary:?}")
        });
    assert_eq!(checked.account, account);
    assert_eq!(checked.claim_pk, claim_keypair.public_key());

    // The seed-only client now CREDITS + MINTS the recovered deposit itself by
    // submitting an on-chain balance proof (the real client proof path; the
    // hermetic helper scripts the shared mock's block-hash ring and hands the
    // server a synthetic proof of `deposit_amount`). `claim_keypair` is
    // identical to what client 2 re-derived at index 0 (same seed), and
    // recovery re-stored it -- exactly the key the recovered client holds.
    common::credit_deposit_via_proof(
        &usdt2,
        &mock,
        usdt_contract,
        &claim_keypair,
        account,
        deposit_amount,
        Duration::from_secs(120),
    )
    .await?;

    // The deposited amount NET of the deposit fee lands in the seed-only
    // client's `USDT_UNIT` balance. Issuance is asynchronous even after the
    // proof tx is accepted, so poll with a timeout.
    let poll_deadline = Instant::now() + Duration::from_secs(30);
    let balance = loop {
        let balance = client2.get_balance_for_unit(USDT_UNIT).await?;
        if balance == Amount::from_msats(net_amount.0) || Instant::now() >= poll_deadline {
            break balance;
        }
        sleep(Duration::from_millis(200)).await;
    };
    assert_eq!(
        balance,
        Amount::from_msats(net_amount.0),
        "the recovered deposit must be creditable+claimable into USDT_UNIT e-cash on the \
         seed-only client"
    );

    // Re-running recovery now finds the deposit CREDITED (via the proof above):
    // it moves from `checked` to `accounts`, with `claimable == 0` (deposit-by-
    // proof already minted the whole balance), and this advances
    // `NextDepositIndex` past index 0.
    let summary2 = usdt2.recover_deposits(20, true).await?;
    assert_eq!(
        summary2.recovered, 1,
        "the now-credited deposit must be rediscovered as already-credited (summary: {summary2:?})"
    );
    assert_eq!(summary2.total_credited, deposit_amount);
    assert_eq!(summary2.total_claimable, UsdtAmount(0));
    let recovered = &summary2.accounts[0];
    assert_eq!(recovered.index, 0);
    assert_eq!(recovered.account, account);
    assert_eq!(recovered.claim_pk, claim_keypair.public_key());
    assert_eq!(recovered.credited, deposit_amount);
    assert_eq!(recovered.claimable, UsdtAmount(0));

    // A subsequent `allocate_deposit` on the recovered client must not collide
    // with the recovered index 0: the second recovery advanced
    // `NextDepositIndex` past it, so the next deposit uses index 1 (a distinct
    // account). The federation is already `Ready` (same shared mock/consensus
    // DB), so this returns immediately; kept for robustness.
    common::await_usdt_ready(&usdt2, Duration::from_secs(60)).await?;
    let (_next_keypair, next_account) = usdt2.allocate_deposit().await?;
    assert_ne!(
        next_account, account,
        "a post-recovery allocate_deposit must not reuse the recovered account"
    );

    Ok(())
}
