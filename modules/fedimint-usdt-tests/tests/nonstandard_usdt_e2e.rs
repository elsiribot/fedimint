//! **USDT-quirk acceptance tests (Goal #2).** The rest of this crate's real-
//! chain e2e tests (`deploy_and_sweep_e2e.rs`, `withdraw_e2e.rs`) deploy a
//! CLEAN, standard ERC-20 (`TestUsdt`, whose `transfer`/`transferFrom` return
//! `bool`). Real mainnet Tether (`TetherToken`,
//! `0xdAC17F958D2ee523a2206206994597C13D831ec7`) is NON-STANDARD, and the
//! master plan flagged "USDT-quirk handling" as an untested risk. These tests
//! re-run the full deploy+sweep and batched-withdrawal paths against a faithful
//! non-standard fixture (`NonStandardUsdt`, see
//! `contracts/NonStandardUsdt.sol` / `tests/fixtures/nonstandard_usdt.json`),
//! proving our ERC-4337 path survives the quirks.
//!
//! # The quirk that matters most: void-returning `transfer`/`transferFrom`
//!
//! Real USDT's `transfer(address,uint256)`/`transferFrom(...)` return NOTHING
//! (the old-Solidity `BasicToken`/`StandardToken` base), unlike the ERC-20
//! standard's `bool`. Our sweep issues `SimpleAccount.execute(usdt, 0,
//! abi.encodeCall(transfer(pool, amount)))` and our withdrawal issues
//! `executeBatch`; `SimpleAccount` does a low-level call and checks ONLY call-
//! success -- it never ABI-decodes a `bool` return. So a void-returning token
//! SHOULD work through our path, but that was an untested assumption. The two
//! federation tests below (`..._via_nonstandard_usdt`) exercise the exact same
//! pipeline as their standard-token siblings, and pass ONLY IF the void return
//! is handled end to end. The `NonStandardUsdt` fixture's Rust binding
//! (`common::INonStandardUsdt`) even declares `transfer` with no return, so the
//! test's own deposit-funding transfer also drives the void wire shape.
//!
//! # The fee quirk (`basisPointsRate` + `maximumFee`)
//!
//! Real USDT carries an owner-settable transfer fee (recipient receives
//! `value - fee`, remainder to `owner`). On mainnet both parameters are 0, so
//! USDT behaves like a plain transfer TODAY. The `NonStandardUsdt` fixture
//! reproduces the mechanism (default 0). `fee_mechanism_reduces_recipient_
//! amount` below proves the mechanism is faithful in ISOLATION (a direct
//! EOA-to- EOA transfer, no federation), while the two federation tests
//! deliberately leave the fee at 0 -- see their in-body `NOTE:` for why a
//! non-zero fee is out of scope for the module path (it would break the
//! module's fixed-amount sweep/withdrawal accounting, which assumes the pool
//! receives exactly the transferred amount, and fixing that is a consensus
//! change out of scope here).
//!
//! Slow (the two federation tests do real DKG + real cggmp21 MPC, several
//! minutes each), except `fee_mechanism_reduces_recipient_amount`, which is a
//! fast pure-anvil check. All skip (rather than fail) if `anvil` isn't
//! available; see `common::spawn_anvil`.

mod common;

use std::sync::Arc;
use std::time::Duration;

use alloy::primitives::{Address, U256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::signers::local::PrivateKeySigner;
use alloy::sol;
use anyhow::{Context as _, bail};
use fedimint_client::ClientHandleArc;
use fedimint_core::PeerId;
use fedimint_core::core::ModuleInstanceId;
use fedimint_core::db::IDatabaseTransactionOpsCoreTyped;
use fedimint_core::runtime::{Instant, sleep};
use fedimint_mintv2_client::MintClientInit as Mintv2ClientInit;
use fedimint_mintv2_common::KIND as MINTV2_KIND;
use fedimint_mintv2_common::config::MintGenParams;
use fedimint_mintv2_server::MintInit as Mintv2Init;
use fedimint_testing::federation::FederationTest;
use fedimint_testing::fixtures::Fixtures;
use fedimint_usdt_client::{UsdtClientInit, UsdtClientModule};
use fedimint_usdt_common::{
    EvmAddress, USDT_UNIT, UsdtAmount, UsdtGenParams, UserOpStatus, WithdrawalStatus,
};
use fedimint_usdt_server::UsdtInit;
use fedimint_usdt_server::db::{PendingUserOpKey, PendingUserOpPrefix};
use fedimint_usdt_server::rpc::{AlloyEvmRpc, IServerEvmRpc};
use futures::StreamExt as _;

sol! {
    #[sol(rpc)]
    interface IEntryPointDeposit {
        function depositTo(address account) external payable;
    }

    #[sol(rpc)]
    interface IErc20Balance {
        function balanceOf(address account) external view returns (uint256);
    }

    // The NON-STANDARD token's owner-only fee setter + accessors, driven only by
    // `fee_mechanism_reduces_recipient_amount`. `transfer` is declared with NO
    // return here (like `common::INonStandardUsdt`), matching the real token.
    #[sol(rpc)]
    interface INonStandardUsdtFee {
        function setParams(uint256 newBasisPoints, uint256 newMaxFee) external;
        function transfer(address to, uint256 amount) external;
        function balanceOf(address account) external view returns (uint256);
        function owner() external view returns (address);
    }
}

/// Comfortably covers the devnet gas bounds' worst-case prefund several times
/// over. Mirrors `deploy_and_sweep_e2e.rs`/`withdraw_e2e.rs`'s identical
/// constant.
const ENTRY_POINT_DEPOSIT_WEI: u128 = 1_000_000_000_000_000_000; // 1 ETH

/// Returns the single `op_hash` this guardian's `PendingUserOp` table currently
/// holds (or `None` if empty / more than one). Mirrors
/// `deploy_and_sweep_e2e.rs`'s identical helper.
async fn find_sole_pending_user_op_hash(
    fed: &FederationTest,
    peer: PeerId,
    module_instance_id: ModuleInstanceId,
) -> Option<[u8; 32]> {
    let db = fed.server_db(peer);
    let mut dbtx = db.begin_transaction_nc().await;
    let (mut isolated, _) = dbtx.to_ref_with_prefix_module_id(module_instance_id);
    let pending: Vec<(PendingUserOpKey, _)> = isolated
        .find_by_prefix(&PendingUserOpPrefix)
        .await
        .collect()
        .await;
    match pending.as_slice() {
        [(PendingUserOpKey(hash), _)] => Some(*hash),
        _ => None,
    }
}

/// Mines `count` empty blocks on `anvil`, advancing its real chain head without
/// sending any transaction. Mirrors `withdraw_e2e.rs`'s identical helper (see
/// its doc comment / `deploy_and_sweep_e2e.rs` for the instant-mine
/// confirmation-depth rationale).
async fn mine_empty_blocks(anvil: &common::AnvilHandle, count: u32) -> anyhow::Result<()> {
    let provider = ProviderBuilder::new().connect_http(anvil.url().parse()?);
    for _ in 0..count {
        provider
            .raw_request::<_, String>("evm_mine".into(), ())
            .await
            .context("failed to mine an anvil block")?;
    }
    Ok(())
}

/// **Deploy-and-sweep against the NON-STANDARD token.** A carbon copy of
/// `deploy_and_sweep_e2e.rs`'s
/// `deposit_account_is_deployed_and_swept_via_real_mpc_and_real_entrypoint`,
/// but the USDT token is the void-`transfer`-returning `NonStandardUsdt`
/// fixture (via `deploy_nonstandard_4337_stack` +
/// `transfer_nonstandard_from_account_1`). Passing proves the deploy+sweep
/// pipeline handles real USDT's void return -- the sweep's
/// `SimpleAccount.execute(transfer(pool, amount))` runs and moves real tokens
/// despite the token pushing no return data.
#[ignore = "needs an ERC-4337 bundler; anvil answers eth_getUserOperationReceipt with -32601. See deploy_and_sweep_e2e.rs for the shared analysis"]
#[tokio::test(flavor = "multi_thread")]
async fn deposit_account_is_deployed_and_swept_via_nonstandard_usdt() -> anyhow::Result<()> {
    let Some(anvil) = common::spawn_anvil().await? else {
        eprintln!(
            "SKIP: anvil not available (set FM_ANVIL_BASE_EXECUTABLE to an anvil binary, or \
             install foundry, and re-run)"
        );
        return Ok(());
    };

    // 1. Deploy the full 4337 stack with the NON-STANDARD USDT token.
    let usdt_holder = common::anvil_account_1_address()?;
    let stack =
        common::deploy_nonstandard_4337_stack(&anvil, usdt_holder, UsdtAmount(50_000_000)).await?;

    // NOTE: the fee mechanism (basisPointsRate/maximumFee) is left at its 0
    // default here, matching mainnet USDT today. A non-zero fee would make the
    // pool receive `amount - fee` while the module credits the full deposit
    // amount, breaking its fixed-amount sweep accounting -- reconciling that is
    // a consensus change out of scope for this test. The fee mechanism's
    // faithfulness is proven in isolation by
    // `fee_mechanism_reduces_recipient_amount`.

    let evm_rpc: Arc<dyn IServerEvmRpc> = AlloyEvmRpc::new(anvil.url())?
        .with_broadcaster(common::ANVIL_ACCOUNT_0_PRIVATE_KEY)?
        .with_entry_point(stack.entry_point)
        .into_dyn();

    // Part A: the module self-deploys its own SimpleAccountFactory; config
    // points at the DERIVED (CREATE2) factory/impl addresses it will deploy
    // at, not a harness-deployed factory.
    let account_factory =
        fedimint_usdt_server::factory_bytecode::derive_account_factory(stack.entry_point);
    let simple_account_impl =
        fedimint_usdt_server::factory_bytecode::derive_simple_account_impl(account_factory);
    let gen_params = UsdtGenParams {
        usdt_contract: stack.usdt,
        chain_id: 31337,
        confirmation_depth: 1,
        entry_point: stack.entry_point,
        account_factory,
        simple_account_impl,
        // Must be > 0 (sec-17 config validation); the broadcaster is the
        // anvil-funded account, so any low value is trivially satisfied.
        broadcaster_min_balance_wei: 1,
        // No Chainlink on anvil: all-zero disables the feed and falls back
        // to `AlloyEvmRpc::STATIC_USDT_PER_ETH_E6` (see Task 4 of the
        // ETH/USD price-feed plan).
        eth_usd_price_feed: EvmAddress([0u8; 20]),
        price_feed_max_staleness_secs: 14_400,
        residual_recovery_recipient: EvmAddress([0u8; 20]),
    };

    // Crediting is now proof-driven, and a deposit-by-proof submission credits
    // AND mints the proven balance in one transaction -- so this federation
    // needs a `mintv2` instance registered as the `USDT_UNIT` primary module
    // (mirroring `withdraw_e2e.rs`) for the proof input to balance.
    let fed = Fixtures::new_primary(Mintv2ClientInit, Mintv2Init)
        .with_extra_module_instance(
            MINTV2_KIND,
            MintGenParams {
                amount_unit: USDT_UNIT,
            },
        )
        .with_module(
            UsdtClientInit,
            UsdtInit::with_evm_rpc(evm_rpc.clone()).with_gen_params(gen_params),
        )
        .new_fed_builder(0)
        .disable_mint_fees()
        .build()
        .await;

    let client: ClientHandleArc = fed.new_client().await;
    let usdt = client.get_first_module::<UsdtClientModule>()?;
    let module_instance_id = usdt.id;
    let peers: Vec<PeerId> = usdt.all_peers().into_iter().collect();
    assert_eq!(
        peers.len(),
        4,
        "this test assumes the default 4-guardian fixture"
    );

    // Part C: wait for the readiness state machine to report Ready (real
    // deployed stack + funded broadcaster) before allocating.
    common::await_usdt_ready(&usdt, Duration::from_secs(60)).await?;
    let (claim_keypair, deposit_account) = usdt.allocate_deposit().await?;
    let code_len_before = evm_rpc.get_code_len(deposit_account).await?;
    assert_eq!(
        code_len_before, 0,
        "the counterfactual deposit account must have no code before the sweep"
    );

    // Challenge B scaffolding: prefund the deposit account's EntryPoint deposit.
    let broadcaster_signer: PrivateKeySigner = common::ANVIL_ACCOUNT_0_PRIVATE_KEY.parse()?;
    let broadcaster_provider = ProviderBuilder::new()
        .wallet(broadcaster_signer)
        .connect_http(anvil.url().parse()?);
    let entry_point_deposit =
        IEntryPointDeposit::new(Address::from(stack.entry_point.0), &broadcaster_provider);
    entry_point_deposit
        .depositTo(Address::from(deposit_account.0))
        .value(U256::from(ENTRY_POINT_DEPOSIT_WEI))
        .send()
        .await
        .context("failed to send EntryPoint.depositTo(deposit_account)")?
        .get_receipt()
        .await
        .context("failed to confirm EntryPoint.depositTo(deposit_account)")?;

    // Fund the deposit account with the NON-STANDARD USDT ONLY (no ETH). This
    // drives `INonStandardUsdt::transfer` (void return) -- if alloy mis-handled
    // the empty return, THIS call would already fail.
    // Comfortably above the live anvil-gas-derived deposit fee the proof path
    // now charges (a few USDT at anvil gas prices / the $3000 fallback).
    let deposit_amount = UsdtAmount(40_000_000);
    common::transfer_nonstandard_from_account_1(
        &anvil,
        stack.usdt,
        deposit_account,
        deposit_amount,
    )
    .await
    .context("failed to fund the counterfactual deposit account with non-standard USDT")?;
    mine_empty_blocks(&anvil, 5).await?;

    // Credit the deposit via the REAL client `eth_getProof` submit flow against
    // the e2e anvil -- NO guardian `balanceOf` poll in the loop (the scanner is
    // gone). `allocate_deposit` handed out index 0, so `submit_deposit_proof(0)`
    // re-derives the same claim key/account and credits the proven
    // (void-`transfer`-funded) balance (minting it net of the live deposit
    // fee) in one transaction.
    common::credit_deposit_via_anvil_proof(&usdt, &anvil, 0, Duration::from_secs(180)).await?;

    let credited_deadline = Instant::now() + Duration::from_secs(120);
    loop {
        let status = usdt.deposit_status(claim_keypair.public_key()).await?;
        if status.credited == deposit_amount {
            break;
        }
        if Instant::now() >= credited_deadline {
            bail!("deposit was never credited before the deadline (last status: {status:?})");
        }
        sleep(Duration::from_millis(500)).await;
    }

    let pending_deadline = Instant::now() + Duration::from_secs(60);
    let op_hash = loop {
        if let Some(hash) = find_sole_pending_user_op_hash(&fed, peers[0], module_instance_id).await
        {
            break hash;
        }
        if Instant::now() >= pending_deadline {
            bail!("no PendingUserOp appeared on peer 0 before the deadline");
        }
        sleep(Duration::from_millis(500)).await;
    };

    // Real MPC signs, `handleOps` runs the void-returning `transfer` inside the
    // deploy-and-sweep UserOp, and every guardian converges on the swept amount.
    for &peer in &peers {
        let deadline = Instant::now() + Duration::from_secs(600);
        loop {
            let pool = usdt.pool_state(peer).await?;
            if pool.balance == deposit_amount {
                break;
            }
            if Instant::now() >= deadline {
                bail!(
                    "guardian {peer} PoolState.balance never converged to the swept amount \
                     (last read {})",
                    pool.balance
                );
            }
            sleep(Duration::from_secs(2)).await;
        }
    }

    // (a) The deposit account was deployed via initCode (code-len 0 -> nonzero).
    let code_len_after = evm_rpc.get_code_len(deposit_account).await?;
    assert!(
        code_len_after > 0,
        "the deposit account must have code after the deploy-and-sweep UserOp \
         (code_len_before={code_len_before}, code_len_after={code_len_after})"
    );

    // (b) The pool's ON-CHAIN non-standard-USDT balance equals the swept amount.
    //     With fee == 0 the pool receives exactly `deposit_amount`; this is the
    //     assertion that would FAIL under a non-zero fee (see the NOTE above),
    //     and it is precisely what proves the void-returning `transfer` moved
    //     real tokens.
    let pool_account = usdt.pool_state(peers[0]).await?.account;
    let read_provider = ProviderBuilder::new().connect_http(anvil.url().parse()?);
    let usdt_token = IErc20Balance::new(Address::from(stack.usdt.0), &read_provider);
    let pool_onchain_balance = usdt_token
        .balanceOf(Address::from(pool_account.0))
        .call()
        .await
        .context("failed to read the pool's post-sweep on-chain USDT balance")?;
    assert_eq!(
        pool_onchain_balance,
        U256::from(deposit_amount.0),
        "the pool's on-chain non-standard-USDT balance must equal the swept amount"
    );

    // (c) Consensus PoolState.balance == swept amount on every guardian, and
    //     every guardian finalized the UserOp.
    for &peer in &peers {
        let pool = usdt.pool_state(peer).await?;
        assert_eq!(
            pool.balance, deposit_amount,
            "guardian {peer}'s consensus PoolState.balance must equal the swept amount"
        );
        let op_status = usdt.userop_status(peer, op_hash).await?.status;
        assert_ne!(
            op_status,
            UserOpStatus::Pending,
            "guardian {peer} must have finalized the UserOp (status was {op_status:?})"
        );
    }

    Ok(())
}

/// **Batched withdrawal against the NON-STANDARD token.** A carbon copy of
/// `withdraw_e2e.rs`'s
/// `withdrawal_is_batched_deployed_and_paid_via_real_mpc_and_real_entrypoint`,
/// but the USDT token is the void-`transfer`-returning `NonStandardUsdt`
/// fixture. Passing proves the withdrawal `executeBatch` path handles real
/// USDT's void return: the pool `SimpleAccount` is deployed by the batch's
/// `initCode` and pays a fresh EOA in real (non-standard) tokens.
#[ignore = "needs an ERC-4337 bundler; anvil answers eth_getUserOperationReceipt with -32601. See deploy_and_sweep_e2e.rs for the shared analysis"]
#[tokio::test(flavor = "multi_thread")]
async fn withdrawal_is_batched_deployed_and_paid_via_nonstandard_usdt() -> anyhow::Result<()> {
    let Some(anvil) = common::spawn_anvil().await? else {
        eprintln!(
            "SKIP: anvil not available (set FM_ANVIL_BASE_EXECUTABLE to an anvil binary, or \
             install foundry, and re-run)"
        );
        return Ok(());
    };

    // 1. Deploy the full 4337 stack with the NON-STANDARD USDT token.
    let usdt_holder = common::anvil_account_1_address()?;
    let stack =
        common::deploy_nonstandard_4337_stack(&anvil, usdt_holder, UsdtAmount(50_000_000)).await?;

    // NOTE: fee left at 0 (mainnet USDT today), for the same reason documented
    // in `deposit_account_is_deployed_and_swept_via_nonstandard_usdt` -- a
    // non-zero fee would make the recipient receive `amount - fee` while the
    // module debits the pool by exactly `amount`, breaking its fixed-amount
    // accounting (a consensus change out of scope here). Faithfulness of the
    // fee mechanism itself is covered by `fee_mechanism_reduces_recipient_amount`.

    let evm_rpc: Arc<dyn IServerEvmRpc> = AlloyEvmRpc::new(anvil.url())?
        .with_broadcaster(common::ANVIL_ACCOUNT_0_PRIVATE_KEY)?
        .with_entry_point(stack.entry_point)
        .into_dyn();

    // Part A: the module self-deploys its own SimpleAccountFactory; config
    // points at the DERIVED (CREATE2) factory/impl addresses it will deploy
    // at, not a harness-deployed factory.
    let account_factory =
        fedimint_usdt_server::factory_bytecode::derive_account_factory(stack.entry_point);
    let simple_account_impl =
        fedimint_usdt_server::factory_bytecode::derive_simple_account_impl(account_factory);
    let gen_params = UsdtGenParams {
        usdt_contract: stack.usdt,
        chain_id: 31337,
        confirmation_depth: 1,
        entry_point: stack.entry_point,
        account_factory,
        simple_account_impl,
        // Must be > 0 (sec-17 config validation); the broadcaster is the
        // anvil-funded account, so any low value is trivially satisfied.
        broadcaster_min_balance_wei: 1,
        // No Chainlink on anvil: all-zero disables the feed and falls back
        // to `AlloyEvmRpc::STATIC_USDT_PER_ETH_E6` (see Task 4 of the
        // ETH/USD price-feed plan).
        eth_usd_price_feed: EvmAddress([0u8; 20]),
        price_feed_max_staleness_secs: 14_400,
        residual_recovery_recipient: EvmAddress([0u8; 20]),
    };

    let fed = Fixtures::new_primary(Mintv2ClientInit, Mintv2Init)
        .with_extra_module_instance(
            MINTV2_KIND,
            MintGenParams {
                amount_unit: USDT_UNIT,
            },
        )
        .with_module(
            UsdtClientInit,
            UsdtInit::with_evm_rpc(evm_rpc.clone()).with_gen_params(gen_params),
        )
        .new_fed_builder(0)
        .disable_mint_fees()
        .build()
        .await;

    let client: ClientHandleArc = fed.new_client().await;
    let usdt = client.get_first_module::<UsdtClientModule>()?;
    let peers: Vec<PeerId> = usdt.all_peers().into_iter().collect();
    assert_eq!(
        peers.len(),
        4,
        "this test assumes the default 4-guardian fixture"
    );

    let broadcaster_signer: PrivateKeySigner = common::ANVIL_ACCOUNT_0_PRIVATE_KEY.parse()?;
    let broadcaster_provider = ProviderBuilder::new()
        .wallet(broadcaster_signer)
        .connect_http(anvil.url().parse()?);
    let entry_point_deposit =
        IEntryPointDeposit::new(Address::from(stack.entry_point.0), &broadcaster_provider);

    // Prefund the pool SimpleAccount's EntryPoint deposit (Challenge B, pool leg).
    let pool_account = usdt.pool_state(peers[0]).await?.account;
    entry_point_deposit
        .depositTo(Address::from(pool_account.0))
        .value(U256::from(ENTRY_POINT_DEPOSIT_WEI))
        .send()
        .await
        .context("failed to send EntryPoint.depositTo(pool_account)")?
        .get_receipt()
        .await
        .context("failed to confirm EntryPoint.depositTo(pool_account)")?;

    // Derive the deposit account and prefund its EntryPoint deposit too.
    // Part C: wait for the readiness state machine to report Ready first.
    common::await_usdt_ready(&usdt, Duration::from_secs(60)).await?;

    // Deposit-by-proof charges the federation's live deposit fee, so the
    // on-chain deposit below is padded by the live quote with margin.
    // `_claim_keypair` is unused because crediting is driven by
    // seed-derivation index (0) below, not the keypair object.
    let (_claim_keypair, deposit_account) = usdt.allocate_deposit().await?;
    assert_eq!(
        evm_rpc.get_code_len(deposit_account).await?,
        0,
        "the counterfactual deposit account must have no code before the sweep"
    );
    entry_point_deposit
        .depositTo(Address::from(deposit_account.0))
        .value(U256::from(ENTRY_POINT_DEPOSIT_WEI))
        .send()
        .await
        .context("failed to send EntryPoint.depositTo(deposit_account)")?
        .get_receipt()
        .await
        .context("failed to confirm EntryPoint.depositTo(deposit_account)")?;

    // Fund the deposit account with the NON-STANDARD USDT ONLY (void transfer):
    // `min_net_deposit_amount` (`5_120_000 == 512 * 10_000`) is the minimum
    // NET e-cash the later withdrawal needs. Deposit-by-proof mints the
    // balance NET of the federation's live deposit fee (a real anvil-gas-
    // derived quote, not scriptable), so pad the on-chain deposit with 2x the
    // current quote as margin -- gas can only realistically fall over the
    // idle blocks that follow, so the double-quote pad comfortably covers the
    // fee actually charged at processing time.
    let min_net_deposit_amount = UsdtAmount(5_120_000);
    let live_deposit_fee = {
        let deadline = Instant::now() + Duration::from_secs(60);
        loop {
            if let Ok(quote) = usdt.deposit_fee_quote().await {
                break quote.fee;
            }
            if Instant::now() >= deadline {
                bail!("deposit_fee_quote never became available before the deadline");
            }
            sleep(Duration::from_millis(300)).await;
        }
    };
    let deposit_amount = UsdtAmount(min_net_deposit_amount.0 + 2 * live_deposit_fee.0);
    common::transfer_nonstandard_from_account_1(
        &anvil,
        stack.usdt,
        deposit_account,
        deposit_amount,
    )
    .await
    .context("failed to fund the counterfactual deposit account with non-standard USDT")?;
    mine_empty_blocks(&anvil, 5).await?;

    // Credit + mint via the REAL client `eth_getProof` submit flow against the
    // e2e anvil (NO guardian `balanceOf` poll). This mints `deposit_amount`
    // net of the live deposit fee as `USDT_UNIT` e-cash in one transaction.
    common::credit_deposit_via_anvil_proof(&usdt, &anvil, 0, Duration::from_secs(180)).await?;
    let claimed_deadline = Instant::now() + Duration::from_secs(30);
    let net_deposit_amount = loop {
        let balance = client.get_balance_for_unit(USDT_UNIT).await?;
        if balance.msats > 0 {
            break UsdtAmount(balance.msats);
        }
        if Instant::now() >= claimed_deadline {
            bail!("USDT e-cash was never minted before the deadline");
        }
        sleep(Duration::from_millis(300)).await;
    };
    assert!(
        net_deposit_amount.0 >= min_net_deposit_amount.0,
        "the minted e-cash balance ({net_deposit_amount}) must comfortably cover the minimum \
         needed for the later withdrawal ({min_net_deposit_amount})"
    );

    // The deploy-and-sweep pipeline sweeps the deposit to the pool (void
    // transfer under `execute`) -- poll to convergence on every guardian.
    for &peer in &peers {
        let deadline = Instant::now() + Duration::from_secs(600);
        loop {
            let pool = usdt.pool_state(peer).await?;
            if pool.balance == deposit_amount {
                break;
            }
            if Instant::now() >= deadline {
                bail!(
                    "guardian {peer} PoolState.balance never converged to the swept amount \
                     before the deadline (last read {})",
                    pool.balance
                );
            }
            sleep(Duration::from_secs(2)).await;
        }
    }
    assert!(
        evm_rpc.get_code_len(deposit_account).await? > 0,
        "the deposit account must have code after the deploy-and-sweep UserOp"
    );

    // Derive a 512-aligned amount/max_fee from the live withdrawal fee quote.
    let quote_deadline = Instant::now() + Duration::from_secs(30);
    let raw_quote = loop {
        let quote = usdt.withdraw_fee_quote(UsdtAmount(1_000_000)).await?;
        if quote.max_fee.0 != 0 {
            break quote.max_fee;
        }
        if Instant::now() >= quote_deadline {
            bail!("withdraw_fee_quote never converged to a nonzero quote before the deadline");
        }
        sleep(Duration::from_millis(300)).await;
    };
    let max_fee = UsdtAmount(raw_quote.0 + raw_quote.0 / 5);
    let target_amount: u64 = 2_000_000;
    let remainder = (target_amount + max_fee.0) % 512;
    let padding = if remainder == 0 { 0 } else { 512 - remainder };
    let amount = UsdtAmount(target_amount + padding);
    assert_eq!(
        (amount.0 + max_fee.0) % 512,
        0,
        "amount + max_fee must be 512-aligned so the withdrawal burns notes with no \
         denomination-rounding dust"
    );
    if amount.0 + max_fee.0 > net_deposit_amount.0 {
        bail!(
            "chosen amount ({amount}) + max_fee ({max_fee}) exceeds the spendable \
             net_deposit_amount ({net_deposit_amount}) -- the live fee quote came back higher \
             than expected"
        );
    }

    // Submit the withdrawal to a fresh recipient EOA.
    let recipient = EvmAddress([0x42; 20]);
    let range = usdt.withdraw(recipient, amount, max_fee).await?;
    let out_point = UsdtClientModule::withdrawal_out_point(&range);

    // Push the real chain head past `batch_interval_blocks()`.
    mine_empty_blocks(&anvil, 15).await?;

    // The batch (needs_deploy = true) deploys the pool via initCode and pays the
    // recipient via a void-returning `transfer` inside `executeBatch`.
    let confirmed_block = usdt
        .await_withdrawal_confirmed(out_point, Duration::from_secs(600))
        .await
        .context("withdrawal never reached WithdrawalState::Confirmed")?;

    // (a) Recipient's ON-CHAIN non-standard-USDT balance == withdrawn amount
    //     (fee == 0, so no reduction).
    let latest_block = evm_rpc.get_block_number().await?;
    let recipient_balance = evm_rpc
        .get_erc20_balance(stack.usdt, recipient, latest_block)
        .await
        .context("failed to read the recipient's on-chain USDT balance")?;
    assert_eq!(
        recipient_balance, amount,
        "the recipient's on-chain non-standard-USDT balance must equal the withdrawn amount"
    );

    // (b) The pool account now has code (batch initCode deployed it).
    assert!(
        evm_rpc.get_code_len(pool_account).await? > 0,
        "the pool account must have code after the first withdrawal batch's initCode deploy"
    );

    // (c) Consensus PoolState.balance debited by exactly `amount` on every
    // guardian.
    let expected_pool_balance = UsdtAmount(deposit_amount.0 - amount.0);
    for &peer in &peers {
        let pool = usdt.pool_state(peer).await?;
        assert_eq!(
            pool.balance, expected_pool_balance,
            "guardian {peer}'s consensus PoolState.balance must be debited by exactly the \
             withdrawn amount"
        );
    }

    // (d) Withdrawal status is Confirmed at the landing block.
    let status = usdt.withdrawal_status(out_point).await?.status;
    assert_eq!(
        status,
        WithdrawalStatus::Confirmed {
            block: confirmed_block
        },
        "withdrawal_status must report Confirmed at the block the UserOp landed"
    );

    Ok(())
}

/// **Fee mechanism, in isolation.** Proves the `NonStandardUsdt` fixture's
/// Quirk-2 fee (`basisPointsRate`/`maximumFee`) is faithful to mainnet USDT: a
/// direct EOA-to-EOA `transfer` with a non-zero fee credits the recipient
/// `value - fee` and the `owner` the `fee`. This deliberately does NOT go
/// through the federation/module -- a non-zero fee breaks the module's fixed-
/// amount sweep/withdrawal accounting (see the federation tests' `NOTE:`), so
/// the module path is exercised only with fee == 0. Fast (pure anvil, no DKG).
#[tokio::test(flavor = "multi_thread")]
async fn fee_mechanism_reduces_recipient_amount() -> anyhow::Result<()> {
    let Some(anvil) = common::spawn_anvil().await? else {
        eprintln!("SKIP: anvil not available");
        return Ok(());
    };

    // Deploy the non-standard token (deployer = anvil account 0 = the token's
    // `owner`), minting the transfer amount to anvil account 1 (the sender).
    let sender = common::anvil_account_1_address()?;
    let transfer_amount = UsdtAmount(2_000_000); // 2 USDT
    let token = common::deploy_nonstandard_usdt(&anvil, sender, transfer_amount).await?;

    // As the owner (account 0), enable a 0.1% fee (10 basis points), capped at
    // 5 whole USDT -- far above the fee this transfer will incur, so the
    // proportional (uncapped) branch is what we assert.
    let owner_signer: PrivateKeySigner = common::ANVIL_ACCOUNT_0_PRIVATE_KEY.parse()?;
    let owner_provider = ProviderBuilder::new()
        .wallet(owner_signer)
        .connect_http(anvil.url().parse()?);
    let token_as_owner = INonStandardUsdtFee::new(Address::from(token.0), &owner_provider);
    let basis_points: u64 = 10;
    token_as_owner
        .setParams(U256::from(basis_points), U256::from(5u64))
        .send()
        .await
        .context("failed to send setParams()")?
        .get_receipt()
        .await
        .context("failed to confirm setParams()")?;

    let owner_address = token_as_owner
        .owner()
        .call()
        .await
        .context("failed to read owner()")?;

    // Transfer as the sender (account 1) to a fresh recipient EOA.
    let recipient = EvmAddress([0x99; 20]);
    let sender_signer: PrivateKeySigner = common::ANVIL_ACCOUNT_1_PRIVATE_KEY.parse()?;
    let sender_provider = ProviderBuilder::new()
        .wallet(sender_signer)
        .connect_http(anvil.url().parse()?);
    let token_as_sender = INonStandardUsdtFee::new(Address::from(token.0), &sender_provider);
    token_as_sender
        .transfer(Address::from(recipient.0), U256::from(transfer_amount.0))
        .send()
        .await
        .context("failed to send fee'd transfer()")?
        .get_receipt()
        .await
        .context("failed to confirm fee'd transfer()")?;

    // fee = value * basisPointsRate / 10000, below the cap.
    let expected_fee = transfer_amount.0 * basis_points / 10_000;
    assert!(
        expected_fee > 0,
        "test misconfigured: the chosen amount/rate must produce a non-zero fee"
    );
    let expected_recipient = transfer_amount.0 - expected_fee;

    let read_provider = ProviderBuilder::new().connect_http(anvil.url().parse()?);
    let token_read = INonStandardUsdtFee::new(Address::from(token.0), &read_provider);
    let recipient_balance = token_read
        .balanceOf(Address::from(recipient.0))
        .call()
        .await
        .context("failed to read recipient balance")?;
    let owner_balance = token_read
        .balanceOf(owner_address)
        .call()
        .await
        .context("failed to read owner balance")?;

    assert_eq!(
        recipient_balance,
        U256::from(expected_recipient),
        "recipient must receive value minus the fee"
    );
    assert_eq!(
        owner_balance,
        U256::from(expected_fee),
        "the owner must accrue exactly the fee"
    );

    Ok(())
}
