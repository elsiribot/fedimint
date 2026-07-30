//! ADVERSARIAL security suite for the deposit-by-proof flow (attack matrix in
//! `.superpowers/sdd/adversary-spec.md`).
//!
//! Each test plays a MALICIOUS client that tries to mint/steal value it does
//! not hold: it constructs a tampered `UsdtInput` directly (via the shared
//! [`fedimint_usdt_tests::attacks`] constructors) and submits it through the
//! real client transaction API
//! ([`UsdtClientModule::submit_crafted_input_for_test`], `test-util` feature),
//! bypassing every honest builder and its client-side gates. The federation is
//! the fast hermetic in-process one (a shared [`MockEvmRpc`] stands in for the
//! EVM chain; no DKG/MPC, no anvil), the same harness the re-enabled
//! `deposit_becomes_claimable_usdt_ecash` acceptance test uses.
//!
//! Every attack asserts the federation REJECTS it (defense holds). An attack
//! that instead sees value ACCEPTED/minted fails the test LOUDLY with a
//! `SECURITY FINDING:` panic -- the failing test IS the bug report. The honest
//! baseline (`attack_01_honest_baseline_credits_and_mints`) proves the "reject"
//! results are not false negatives: a legit proof DOES credit + mint exactly.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::MockEvmRpc;
use fedimint_client::ClientHandleArc;
use fedimint_core::Amount;
use fedimint_core::runtime::{Instant, sleep};
use fedimint_core::secp256k1::Keypair;
use fedimint_mintv2_client::MintClientInit as Mintv2ClientInit;
use fedimint_mintv2_common::KIND as MINTV2_KIND;
use fedimint_mintv2_common::config::MintGenParams;
use fedimint_mintv2_server::MintInit as Mintv2Init;
use fedimint_testing::federation::FederationTest;
use fedimint_testing::fixtures::Fixtures;
use fedimint_usdt_client::api::UsdtFederationApi as _;
use fedimint_usdt_client::{CraftedInputOutcome, UsdtClientInit, UsdtClientModule};
use fedimint_usdt_common::{EvmAddress, USDT_UNIT, UsdtAmount};
use fedimint_usdt_server::UsdtInit;
use fedimint_usdt_tests::attacks::{self, Attack};

/// USDT contract address every guardian's mock scripts balances for (the
/// module's default `UsdtGenParams::usdt_contract` placeholder).
const USDT_CONTRACT: EvmAddress = EvmAddress([0u8; 20]);

/// 512-msat-aligned so a credit's minted e-cash is exactly representable by the
/// `mintv2` primary module with no rounding dust (lets the baseline assert
/// EXACT equality).
const DEPOSIT_AMOUNT: UsdtAmount = UsdtAmount(2_560_000);

/// A federation with the USDT-denominated `mintv2` primary plus the usdt module
/// wired to `mock` as every guardian's EVM RPC (mirrors `tests/tests.rs`'s
/// `dual_mint_fixtures`; duplicated here because a `tests/` binary cannot
/// import another `tests/` binary's free items).
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

/// Boots a hermetic federation and drives the usdt module to `Ready` (so
/// `allocate_deposit` is permitted), returning the live fed (kept alive by the
/// caller), a client, and the shared mock. Mirrors the prologue of
/// `deposit_becomes_claimable_usdt_ecash`.
async fn boot_ready() -> anyhow::Result<(FederationTest, ClientHandleArc, Arc<MockEvmRpc>)> {
    let mock = Arc::new(MockEvmRpc::new());
    mock.set_chain_id(31337);
    mock.set_block_number(100);

    let fed = dual_mint_fixtures(mock.clone())
        .new_fed_builder(0)
        .disable_mint_fees()
        .build()
        .await;
    let client: ClientHandleArc = fed.new_client().await;
    let usdt = client.get_first_module::<UsdtClientModule>()?;

    let group_public_key = client.api().with_module(usdt.id).group_public_key().await?;
    common::mock_ready_stack(
        &mock,
        &group_public_key,
        usdt.config().entry_point,
        usdt.config().account_factory,
        usdt.config().simple_account_impl,
    );
    common::await_usdt_ready(&usdt, Duration::from_secs(60)).await?;

    Ok((fed, client, mock))
}

/// Waits for the block-hash ring to anchor a confirmation-deep block strictly
/// above `floor` and returns its height. `floor == 0` => any anchored block.
async fn wait_anchored_above(usdt: &UsdtClientModule, floor: u64) -> anyhow::Result<u64> {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let anchored = usdt.latest_anchored_block().await?;
        if anchored.latest > floor {
            return Ok(anchored.latest);
        }
        if Instant::now() >= deadline {
            anyhow::bail!("block-hash ring never anchored a block above {floor}");
        }
        sleep(Duration::from_millis(200)).await;
    }
}

/// Waits for the block-hash ring to anchor a confirmation-deep block and
/// returns its height (the newest block a proof can safely target).
async fn latest_anchored(usdt: &UsdtClientModule) -> anyhow::Result<u64> {
    wait_anchored_above(usdt, 0).await
}

/// The current USDT-denominated e-cash balance (msats).
async fn usdt_balance(client: &ClientHandleArc) -> anyhow::Result<Amount> {
    client.get_balance_for_unit(USDT_UNIT).await
}

/// Drives a single adversarial [`Attack`] to its verdict against the hermetic
/// fed and asserts the defense held:
/// - scripts the mock's block-hash if the attack needs a KNOWN anchor;
/// - submits the crafted input via the client tx API, signed by `keys`;
/// - if the fed ACCEPTED it (minted value): panic with a `SECURITY FINDING:`;
/// - retries transient pre-convergence rejections when an anchor was scripted;
/// - asserts the terminal rejection is the expected class and that the client's
///   USDT balance did not move (nothing was credited).
async fn assert_attack_rejected(
    usdt: &UsdtClientModule,
    client: &ClientHandleArc,
    mock: &MockEvmRpc,
    keys: Vec<Keypair>,
    attack: Attack,
) -> anyhow::Result<()> {
    if let Some((block, hash)) = attack.hermetic_anchor {
        mock.set_block_hash(block, hash);
    }

    let balance_before = usdt_balance(client).await?;
    let deadline = Instant::now() + Duration::from_secs(30);

    loop {
        let outcome = usdt
            .submit_crafted_input_for_test(attack.input.clone(), keys.clone(), attack.declared)
            .await?;

        match outcome {
            CraftedInputOutcome::Accepted { minted } => {
                panic!(
                    "SECURITY FINDING: attack `{}` ({}) was ACCEPTED and minted {} of USDT e-cash \
                     -- the defense BREACHED. Crafted input: {:?}",
                    attack.name, attack.description, minted, attack.input,
                );
            }
            CraftedInputOutcome::Rejected { reason } => {
                if attack.expected.matches(&reason) {
                    // Defense held with the expected rejection.
                    let balance_after = usdt_balance(client).await?;
                    assert_eq!(
                        balance_after, balance_before,
                        "SECURITY FINDING: attack `{}` was rejected ({reason}) yet the USDT \
                         balance changed from {balance_before} to {balance_after}",
                        attack.name,
                    );
                    return Ok(());
                }

                // Not (yet) the expected rejection. When we scripted an anchor,
                // the ring may still be converging to it (a transient
                // NotAnchored/Invalid before the scripted hash is voted in);
                // retry until it converges or the deadline passes.
                if attack.hermetic_anchor.is_some() && Instant::now() < deadline {
                    sleep(Duration::from_millis(300)).await;
                    continue;
                }

                panic!(
                    "attack `{}` was rejected, but with an UNEXPECTED reason (wanted {}): {reason}",
                    attack.name,
                    attack.expected.label(),
                );
            }
        }
    }
}

/// #1 HONEST BASELINE (control): a legit proof of a genuinely-derived deposit
/// account credits AND mints exactly the deposited amount. Proves the flow
/// works and that the matrix's "reject" outcomes are not false negatives.
#[tokio::test(flavor = "multi_thread")]
async fn attack_01_honest_baseline_credits_and_mints() -> anyhow::Result<()> {
    let (fed, client, mock) = boot_ready().await?;
    let usdt = client.get_first_module::<UsdtClientModule>()?;

    let (claim_keypair, account) = usdt.allocate_deposit().await?;
    common::credit_deposit_via_proof(
        &usdt,
        &mock,
        USDT_CONTRACT,
        &claim_keypair,
        account,
        DEPOSIT_AMOUNT,
        Duration::from_secs(120),
    )
    .await?;

    // Poll: issuance is async even after the deposit-proof tx is accepted.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let balance = usdt_balance(&client).await?;
        if balance == Amount::from_msats(DEPOSIT_AMOUNT.0) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "honest deposit-by-proof did not mint {DEPOSIT_AMOUNT} (last balance {balance})"
        );
        sleep(Duration::from_millis(200)).await;
    }

    drop(fed);
    Ok(())
}

/// #2 FORGED BALANCE: a proof claiming more than the anchored state root commits
/// to -> anchor mismatch, `DepositProofInvalid`.
#[tokio::test(flavor = "multi_thread")]
async fn attack_02_forged_balance_rejected() -> anyhow::Result<()> {
    let (fed, client, mock) = boot_ready().await?;
    let usdt = client.get_first_module::<UsdtClientModule>()?;

    let (claim_keypair, account) = usdt.allocate_deposit().await?;
    let block = latest_anchored(&usdt).await?;
    let attack = attacks::attack_forged_balance(
        USDT_CONTRACT,
        claim_keypair.public_key(),
        account,
        block,
        UsdtAmount(999_999_999_999),
    );
    assert_attack_rejected(&usdt, &client, &mock, vec![claim_keypair], attack).await?;

    drop(fed);
    Ok(())
}

/// #3 WRONG ACCOUNT: a genuine, anchored proof of account A's balance submitted
/// under a claim key for account B credits nothing (verifies against B's
/// storage key -> proof-of-absence -> proven 0, `DepositProofStale`).
#[tokio::test(flavor = "multi_thread")]
async fn attack_03_wrong_account_credits_nothing() -> anyhow::Result<()> {
    let (fed, client, mock) = boot_ready().await?;
    let usdt = client.get_first_module::<UsdtClientModule>()?;

    // B is the submitting claim key; A is a genuine, unrelated account whose
    // (real) balance we prove but must not be able to steal into B.
    let (claim_keypair_b, account_b) = usdt.allocate_deposit().await?;
    let account_a = EvmAddress([0x99; 20]);
    assert_ne!(account_a, account_b);

    let block = latest_anchored(&usdt).await?;
    let attack = attacks::attack_wrong_account(
        USDT_CONTRACT,
        claim_keypair_b.public_key(),
        account_a,
        block,
        UsdtAmount(500_000_000),
    );
    assert_attack_rejected(&usdt, &client, &mock, vec![claim_keypair_b], attack).await?;

    drop(fed);
    Ok(())
}

/// #4 UNANCHORED BLOCK: a proof against a block the ring never anchored ->
/// `DepositProofNotAnchored`.
#[tokio::test(flavor = "multi_thread")]
async fn attack_04_unanchored_block_rejected() -> anyhow::Result<()> {
    let (fed, client, mock) = boot_ready().await?;
    let usdt = client.get_first_module::<UsdtClientModule>()?;

    let (claim_keypair, account) = usdt.allocate_deposit().await?;
    let block = latest_anchored(&usdt).await?;
    let attack = attacks::attack_unanchored(
        USDT_CONTRACT,
        claim_keypair.public_key(),
        account,
        // Far past the newest anchored, confirmation-deep block: never in the ring.
        block + 10_000,
        UsdtAmount(500_000_000),
    );
    assert_attack_rejected(&usdt, &client, &mock, vec![claim_keypair], attack).await?;

    drop(fed);
    Ok(())
}

/// #5 FORGED HEADER: a proof whose header no longer hashes to the anchored ring
/// hash -> `DepositProofInvalid` (anchor mismatch).
#[tokio::test(flavor = "multi_thread")]
async fn attack_05_forged_header_rejected() -> anyhow::Result<()> {
    let (fed, client, mock) = boot_ready().await?;
    let usdt = client.get_first_module::<UsdtClientModule>()?;

    let (claim_keypair, account) = usdt.allocate_deposit().await?;
    let block = latest_anchored(&usdt).await?;
    let attack = attacks::attack_forged_header(
        USDT_CONTRACT,
        claim_keypair.public_key(),
        account,
        block,
        UsdtAmount(500_000_000),
    );
    assert_attack_rejected(&usdt, &client, &mock, vec![claim_keypair], attack).await?;

    drop(fed);
    Ok(())
}

/// #6 REPLAY / DOUBLE-SUBMIT: resubmit an already-credited proof -> stale
/// (delta 0), no re-credit. Submits the crafted input DIRECTLY (bypassing the
/// honest builder's own delta==0 client-side gate) to prove the SERVER rejects
/// it.
#[tokio::test(flavor = "multi_thread")]
async fn attack_06_replay_rejected() -> anyhow::Result<()> {
    let (fed, client, mock) = boot_ready().await?;
    let usdt = client.get_first_module::<UsdtClientModule>()?;

    let (claim_keypair, account) = usdt.allocate_deposit().await?;
    // Honest credit first (anchors the proof's hash and sets credited == amount).
    common::credit_deposit_via_proof(
        &usdt,
        &mock,
        USDT_CONTRACT,
        &claim_keypair,
        account,
        DEPOSIT_AMOUNT,
        Duration::from_secs(120),
    )
    .await?;

    // Rebuild the exact same proof the honest credit anchored, at the same
    // block, and replay it raw. The ring still holds its hash, so it verifies
    // and is rejected on the zero delta (not the anchor).
    let block = latest_anchored(&usdt).await?;
    let (proof, hash) =
        attacks::synthetic_deposit_proof(USDT_CONTRACT, account, DEPOSIT_AMOUNT.0, block);
    mock.set_block_hash(block, hash);
    let attack = attacks::attack_replay(claim_keypair.public_key(), proof, DEPOSIT_AMOUNT);
    assert_attack_rejected(&usdt, &client, &mock, vec![claim_keypair], attack).await?;

    drop(fed);
    Ok(())
}

/// #7 OVER-MINT: after a legit deposit-by-proof credit (which advances both
/// `credited` and `claimed`), a legacy `V0` claim tries to re-mint the value.
/// `available == 0` -> `InsufficientCredit`.
#[tokio::test(flavor = "multi_thread")]
async fn attack_07_over_mint_via_v0_rejected() -> anyhow::Result<()> {
    let (fed, client, mock) = boot_ready().await?;
    let usdt = client.get_first_module::<UsdtClientModule>()?;

    let (claim_keypair, account) = usdt.allocate_deposit().await?;
    common::credit_deposit_via_proof(
        &usdt,
        &mock,
        USDT_CONTRACT,
        &claim_keypair,
        account,
        DEPOSIT_AMOUNT,
        Duration::from_secs(120),
    )
    .await?;

    // Try to re-claim the already-minted delta via the legacy V0 path. The V0
    // input's pub_key is the account's stored claim_pk, so it must be signed by
    // the same claim keypair.
    let attack = attacks::attack_over_mint_v0(account, DEPOSIT_AMOUNT);
    assert_attack_rejected(&usdt, &client, &mock, vec![claim_keypair], attack).await?;

    drop(fed);
    Ok(())
}

/// #8 OVERSIZE: a proof exceeding `MAX_DEPOSIT_PROOF_BYTES` -> rejected by the
/// size cap before verification (`DepositProofInvalid`, "oversized").
#[tokio::test(flavor = "multi_thread")]
async fn attack_08_oversize_rejected() -> anyhow::Result<()> {
    let (fed, client, mock) = boot_ready().await?;
    let usdt = client.get_first_module::<UsdtClientModule>()?;

    let (claim_keypair, account) = usdt.allocate_deposit().await?;
    let block = latest_anchored(&usdt).await?;
    let attack = attacks::attack_oversize(
        USDT_CONTRACT,
        claim_keypair.public_key(),
        account,
        block,
        UsdtAmount(500_000_000),
    );
    assert_attack_rejected(&usdt, &client, &mock, vec![claim_keypair], attack).await?;

    drop(fed);
    Ok(())
}

/// #9 STALE-GROWTH: after crediting balance X at a newer block, prove an OLDER
/// block where the balance was smaller -> delta 0, no re-credit (high-water
/// monotonic), `DepositProofStale`.
#[tokio::test(flavor = "multi_thread")]
async fn attack_09_stale_growth_rejected() -> anyhow::Result<()> {
    let (fed, client, mock) = boot_ready().await?;
    let usdt = client.get_first_module::<UsdtClientModule>()?;

    let (claim_keypair, account) = usdt.allocate_deposit().await?;
    // Credit a LARGER balance at the newest anchored block (sets high-water).
    common::credit_deposit_via_proof(
        &usdt,
        &mock,
        USDT_CONTRACT,
        &claim_keypair,
        account,
        DEPOSIT_AMOUNT,
        Duration::from_secs(120),
    )
    .await?;

    // Advance the mock chain head so the ring anchors a DISTINCT block (the
    // observer anchors only the single newest confirmation-deep block per tick,
    // and the honest credit above already pinned the prior latest block to its
    // own hash). Then prove that block with a SMALLER balance: the balance
    // high-water (credited) dominates, so the delta is 0 regardless of block
    // ordering -- the monotonicity defense is on the credited BALANCE.
    let credit_block = latest_anchored(&usdt).await?;
    mock.set_block_number(100 + 10);
    let other_block = wait_anchored_above(&usdt, credit_block).await?;
    let attack = attacks::attack_stale_growth(
        USDT_CONTRACT,
        claim_keypair.public_key(),
        account,
        other_block,
        UsdtAmount(DEPOSIT_AMOUNT.0 / 2),
    );
    assert_attack_rejected(&usdt, &client, &mock, vec![claim_keypair], attack).await?;

    drop(fed);
    Ok(())
}
