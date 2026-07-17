mod common;

use std::sync::Arc;
use std::time::Duration;

use common::MockEvmRpc;
use fedimint_client::ClientHandleArc;
use fedimint_core::runtime::sleep;
use fedimint_core::{Amount, secp256k1};
use fedimint_mint_client::{MintClientInit, MintClientModule};
use fedimint_mint_server::MintInit;
use fedimint_mintv2_client::MintClientInit as Mintv2ClientInit;
use fedimint_mintv2_common::KIND as MINTV2_KIND;
use fedimint_mintv2_common::config::MintGenParams;
use fedimint_mintv2_server::MintInit as Mintv2Init;
use fedimint_testing::fixtures::Fixtures;
use fedimint_usdt_client::api::UsdtFederationApi;
use fedimint_usdt_client::{UsdtClientInit, UsdtClientModule};
use fedimint_usdt_common::{EvmAddress, USDT_UNIT, UsdtAmount};
use fedimint_usdt_server::UsdtInit;

fn fixtures() -> Fixtures {
    Fixtures::new_primary(MintClientInit, MintInit).with_module(UsdtClientInit, UsdtInit::default())
}

/// A federation with TWO mintv2 instances (the default Bitcoin-denominated
/// primary plus a second instance denominated in [`USDT_UNIT`], mirroring the
/// Phase 4.5 dual-mint fixture in `fedimint-mintv2-tests`) and the usdt
/// module wired up with `mock` as EVERY guardian's [`fedimint_usdt_server::
/// rpc::IServerEvmRpc`] (via [`UsdtInit::with_evm_rpc`]). Sharing one mock
/// across all guardians is what lets their independently-run deposit-checker
/// tasks observe identical balances and reach the deposit-observation
/// consensus threshold.
///
/// The usdt module's claim path funds transactions in `USDT_UNIT`
/// (`fedimint_usdt_server::process_input`), so the client needs a primary
/// module registered for that unit to balance/mint the claimed e-cash into —
/// the second mintv2 instance serves that role.
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

/// Boots a federation with the usdt module attached alongside mint (the
/// fee-paying primary module). `fedimint-testing` performs trusted-dealer
/// config generation (not `distributed_gen`), so this exercises
/// `UsdtInit::trusted_dealer_gen`, client-side module initialization, and the
/// `group_public_key` diagnostic API endpoint added in this phase.
#[tokio::test(flavor = "multi_thread")]
async fn federation_boots_with_usdt_module_and_serves_group_public_key() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_not_degraded().await;
    let (client1, client2): (ClientHandleArc, ClientHandleArc) = fed.two_clients().await;

    // The client module must have initialized successfully for both clients,
    // proving their `UsdtClientConfig` (with a `group_public_key`) was loaded
    // from the trusted-dealer-generated consensus config.
    let usdt1 = client1.get_first_module::<UsdtClientModule>()?;
    let usdt2 = client2.get_first_module::<UsdtClientModule>()?;

    // The mint module must also be usable, confirming the federation is a
    // healthy, fully functioning fedimint federation with usdt attached.
    let _mint_module = client1.get_first_module::<MintClientModule>()?;

    // Exercise the `group_public_key` diagnostic endpoint end-to-end: it
    // proves the DKG(trusted-dealer)-produced config is loaded on the server
    // side and queryable over the wire, and that every guardian agrees on the
    // same group public key.
    let key1 = client1
        .api()
        .with_module(usdt1.id)
        .group_public_key()
        .await?;
    let key2 = client2
        .api()
        .with_module(usdt2.id)
        .group_public_key()
        .await?;

    assert_eq!(
        key1, key2,
        "all guardians must agree on the same DKG group public key"
    );
    assert_eq!(
        key1.serialize().len(),
        33,
        "group_public_key must be a valid compressed secp256k1 public key"
    );

    Ok(())
}

/// Derivation-parity test (Task 10): the client's `deposit_address` must
/// compute the exact same address as `fedimint_usdt_common::
/// derive_deposit_account` given the same group public key and claim key, so
/// the two independent call sites (client-side derivation vs. what the
/// server derives and watches) can never silently diverge.
#[tokio::test(flavor = "multi_thread")]
async fn client_deposit_address_matches_common_derivation() -> anyhow::Result<()> {
    let fed = fixtures().new_fed_not_degraded().await;
    let client: ClientHandleArc = fed.new_client().await;

    let usdt = client.get_first_module::<UsdtClientModule>()?;
    let group_public_key = client.api().with_module(usdt.id).group_public_key().await?;

    let claim_keypair =
        secp256k1::Keypair::new(secp256k1::SECP256K1, &mut secp256k1::rand::thread_rng());
    let claim_pk = claim_keypair.public_key();

    let expected = fedimint_usdt_common::derive_deposit_account(&group_public_key, &claim_pk);
    let actual = usdt.deposit_address(&claim_pk);

    assert_eq!(
        actual, expected,
        "client deposit_address must match fedimint_usdt_common::derive_deposit_account"
    );

    Ok(())
}

/// **Phase 5 gating acceptance test.** Drives the full deposit -> claim ->
/// USDT-denominated e-cash flow over a hermetic in-process federation: a
/// shared [`MockEvmRpc`] stands in for the EVM chain (every guardian reads
/// the exact same balances, so their independently-run block-count pollers
/// and deposit-checker tasks reach deposit-observation consensus on their own
/// 1s test-interval timers -- no test hook forcing progress), and the second
/// mintv2 instance (denominated in [`USDT_UNIT`]) mints the claimed e-cash.
#[tokio::test(flavor = "multi_thread")]
async fn deposit_becomes_claimable_usdt_ecash() -> anyhow::Result<()> {
    let mock = Arc::new(MockEvmRpc::new());
    // The usdt module's default `UsdtGenParams::usdt_contract`
    // (`fedimint_usdt_common::UsdtGenParams::default`), so the mock must
    // script balances for this exact token address.
    let usdt_contract = EvmAddress([0u8; 20]);
    mock.set_chain_id(31337);
    // Well past `confirmation_depth: 1` so the checker's read block is never
    // ahead of this guardian's cached head.
    mock.set_block_number(100);

    // Mint fees disabled: this test asserts the USDT-denominated e-cash
    // balance is *exactly* the deposited amount, which would otherwise be
    // reduced by the USDT-`mintv2` instance's (`mintv2` fee schedule,
    // irrelevant to what this test is verifying: deposit-detection consensus
    // and claim correctness, not fee accounting).
    let fed = dual_mint_fixtures(mock.clone())
        .new_fed_builder(0)
        .disable_mint_fees()
        .build()
        .await;
    let client: ClientHandleArc = fed.new_client().await;
    let usdt = client.get_first_module::<UsdtClientModule>()?;

    // 1. Derive a deposit address.
    let (claim_keypair, account) = usdt.allocate_deposit().await?;

    // 2. Simulate the confirmed on-chain USDT transfer (confirmed as of block 10,
    //    well behind the chain head of 100). `2_560_000` is a multiple of 512 msat
    //    (mintv2's smallest client denomination, `fedimint_mintv2_common::config::
    //    client_denominations`, `Denomination(9) == 2^9`), so the claimed amount is
    //    exactly representable as e-cash notes with no denomination-rounding dust,
    //    letting step 4 assert *exact* equality below.
    mock.set_erc20_balance_at(usdt_contract, account, 10, UsdtAmount(2_560_000));

    // 3. Client checks + claims; guardians observe (block-count poller +
    //    deposit-checker on their 1s test ticks) and credit at threshold, then the
    //    client submits the claim transaction. A generous deadline: consensus
    //    sessions + the 1s poll ticks need real wall-clock time.
    usdt.check_and_claim(&claim_keypair, Duration::from_secs(120))
        .await?;

    // 4. The USDT-denominated e-cash balance equals the deposit. Issuance is
    //    asynchronous even after the claim transaction is accepted, so poll with a
    //    timeout rather than asserting on the first read.
    let poll_deadline = fedimint_core::runtime::Instant::now() + Duration::from_secs(30);
    let balance = loop {
        let balance = client.get_balance_for_unit(USDT_UNIT).await?;
        if balance == Amount::from_msats(2_560_000)
            || fedimint_core::runtime::Instant::now() >= poll_deadline
        {
            break balance;
        }
        sleep(Duration::from_millis(200)).await;
    };
    assert_eq!(balance, Amount::from_msats(2_560_000));

    // 5. Replay/double-claim of the same account is rejected: every credited msat
    //    was already claimed, so the deposit never becomes claimable again and
    //    `check_and_claim` must time out with an error. The balance must also not
    //    have moved.
    let replay = usdt
        .check_and_claim(&claim_keypair, Duration::from_secs(5))
        .await;
    assert!(
        replay.is_err(),
        "a second claim of an already-fully-claimed account must not succeed"
    );
    assert_eq!(
        client.get_balance_for_unit(USDT_UNIT).await?,
        Amount::from_msats(2_560_000),
        "a rejected replay must not change the USDT-denominated balance"
    );

    Ok(())
}
