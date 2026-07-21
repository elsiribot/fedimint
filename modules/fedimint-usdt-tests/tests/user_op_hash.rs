//! **Phase 7 Task 3 gating acceptance test.** Pins off-chain
//! `fedimint_usdt_common::user_op::user_op_hash`'s v0.7 packing/hash
//! formula against the real, anvil-deployed `EntryPoint.getUserOpHash`: for
//! several representative deploy-and-sweep-shaped `UnsignedUserOp`s, the two
//! must agree byte-for-byte. This retires the master plan's #1 Phase-7 risk
//! ("v0.7 packing/hash subtleties").
//!
//! Skips (rather than fails) if `anvil` isn't available in this
//! environment; see `common::spawn_anvil`.

mod common;

use alloy::primitives::{Address, U256};
use alloy::providers::ProviderBuilder;
use alloy::sol;
use anyhow::Context as _;
use fedimint_usdt_common::EvmAddress;
use fedimint_usdt_common::user_op::{UnsignedUserOp, user_op_hash};

sol! {
    /// Mirrors `fedimint_usdt_common::user_op::PackedUserOperation`
    /// field-for-field. A distinct (test-crate-local) Rust type from a
    /// separate `sol!` invocation, but the same underlying
    /// `alloy-primitives`/`alloy-sol-types` versions (workspace-pinned to a
    /// single copy -- see this workspace's root `Cargo.toml` comment on
    /// `alloy-primitives`), so its fields are exactly
    /// `Address`/`U256`/`Bytes`/`FixedBytes<32>`, letting
    /// `to_rpc_packed_user_op` below copy fields directly with no
    /// conversion.
    struct PackedUserOperation {
        address sender;
        uint256 nonce;
        bytes initCode;
        bytes callData;
        bytes32 accountGasLimits;
        uint256 preVerificationGas;
        bytes32 gasFees;
        bytes paymasterAndData;
        bytes signature;
    }

    #[sol(rpc)]
    interface IEntryPointUserOpHash {
        function getUserOpHash(PackedUserOperation calldata userOp) external view returns (bytes32);
    }
}

/// Converts the `-common` crate's `PackedUserOperation` into this test's own
/// `sol!`-generated type of the same shape, so it can be passed to the
/// `#[sol(rpc)]`-generated `getUserOpHash` binding.
fn to_rpc_packed_user_op(
    p: &fedimint_usdt_common::user_op::PackedUserOperation,
) -> PackedUserOperation {
    PackedUserOperation {
        sender: p.sender,
        nonce: p.nonce,
        initCode: p.initCode.clone(),
        callData: p.callData.clone(),
        accountGasLimits: p.accountGasLimits,
        preVerificationGas: p.preVerificationGas,
        gasFees: p.gasFees,
        paymasterAndData: p.paymasterAndData.clone(),
        signature: p.signature.clone(),
    }
}

/// A representative deploy-and-sweep-shaped `UnsignedUserOp`: non-empty
/// `initCode` (a `SimpleAccountFactory.createAccount`-shaped selector plus
/// dummy args -- this test only hashes the op, it never executes it, so the
/// bytes need not be a real, callable `createAccount` calldata), non-empty
/// `callData` (an `execute`-shaped selector plus dummy args), and a
/// paymaster-and-data blob shaped like `paymaster_address ‖
/// paymasterVerificationGasLimit(16) ‖ paymasterPostOpGasLimit(16) ‖
/// paymasterData`. `deploy` toggles whether `initCode` is populated (an
/// already-deployed account's UserOp has an empty `initCode`), matching
/// this test's "with/without initCode" coverage requirement.
fn deploy_and_sweep_shaped_op(
    sender: EvmAddress,
    paymaster: EvmAddress,
    nonce: u64,
    deploy: bool,
) -> UnsignedUserOp {
    let init_code = if deploy {
        let mut bytes = vec![0xa2, 0x8b, 0x2f, 0x53]; // arbitrary 4-byte selector
        bytes.extend_from_slice(&[0x11; 20]); // dummy owner arg
        bytes.extend_from_slice(&[0u8; 32]); // dummy salt arg
        bytes
    } else {
        vec![]
    };

    let mut call_data = vec![0xb6, 0x1d, 0x27, 0xf6]; // arbitrary 4-byte selector
    call_data.extend_from_slice(&[0x22; 20]); // dummy `dest` arg (USDT contract)
    call_data.extend_from_slice(&[0u8; 32]); // dummy `value` arg (0)
    call_data.extend_from_slice(&[0x33; 4]); // dummy inner-calldata selector
    call_data.extend_from_slice(&[0x44; 20]); // dummy `to` arg (pool)
    call_data.extend_from_slice(&[0u8; 24]); // dummy `amount` padding
    call_data.extend_from_slice(&1_500_000u64.to_be_bytes()); // dummy `amount`

    let mut paymaster_and_data = paymaster.0.to_vec();
    paymaster_and_data.extend_from_slice(&50_000u128.to_be_bytes()); // paymasterVerificationGasLimit
    paymaster_and_data.extend_from_slice(&30_000u128.to_be_bytes()); // paymasterPostOpGasLimit
    paymaster_and_data.extend_from_slice(&[0xde, 0xad]); // arbitrary paymasterData tail

    UnsignedUserOp {
        sender,
        nonce: U256::from(nonce),
        init_code,
        call_data,
        verification_gas_limit: 150_000,
        call_gas_limit: 100_000,
        pre_verification_gas: U256::from(60_000u64),
        max_priority_fee_per_gas: 1_500_000_000,
        max_fee_per_gas: 30_000_000_000,
        paymaster_and_data,
    }
}

#[tokio::test]
async fn user_op_hash_matches_entry_point_get_user_op_hash() -> anyhow::Result<()> {
    let Some(anvil) = common::spawn_anvil().await? else {
        eprintln!(
            "SKIP: anvil not available (set FM_ANVIL_BASE_EXECUTABLE to an anvil binary, or \
             install foundry, and re-run)"
        );
        return Ok(());
    };

    let usdt_holder = EvmAddress([0x42; 20]);
    let stack =
        common::deploy_4337_stack(&anvil, usdt_holder, fedimint_usdt_common::UsdtAmount(0)).await?;

    let provider = ProviderBuilder::new().connect_http(anvil.url().parse()?);
    let entry_point = IEntryPointUserOpHash::new(Address::from(stack.entry_point.0), &provider);

    // A counterfactual (not-yet-deployed) `SimpleAccount` address stands in
    // for `sender`; `getUserOpHash` is a pure function of the op's fields
    // plus `address(this)`/`block.chainid`, so `sender` need not actually
    // exist on chain for this test.
    let sender = EvmAddress([0x55; 20]);

    let ops = [
        // With initCode (first-time deploy-and-sweep).
        deploy_and_sweep_shaped_op(sender, stack.paymaster, 0, true),
        // Without initCode (already-deployed account's sweep).
        deploy_and_sweep_shaped_op(sender, stack.paymaster, 1, false),
    ];

    for (i, op) in ops.iter().enumerate() {
        let offchain = user_op_hash(op, stack.entry_point, 31337);

        let packed = to_rpc_packed_user_op(&op.pack());
        let onchain = entry_point
            .getUserOpHash(packed)
            .call()
            .await
            .with_context(|| format!("EntryPoint.getUserOpHash eth_call failed for op[{i}]"))?;

        assert_eq!(
            offchain,
            onchain.0,
            "off-chain user_op_hash must match on-chain EntryPoint.getUserOpHash for op[{i}] \
             (deploy={})",
            i == 0
        );
    }

    Ok(())
}
