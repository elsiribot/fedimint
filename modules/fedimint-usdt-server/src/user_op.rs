//! Phase 7 Task 4: turning a [`UnsignedUserOp`] into an on-chain effect.
//!
//! This module is guardian-LOCAL plumbing only -- no consensus logic lives
//! here (that is Phase 7 Task 5). It provides:
//! - [`build_deploy_and_sweep_userop`]: builds the deploy-and-sweep
//!   `UnsignedUserOp` for a counterfactual deposit account (`initCode` +
//!   `callData` assembly, static gas bounds).
//! - [`assemble_eth_signature`]: turns a compact `(r, s)` secp256k1 signature
//!   (the shape both the Phase-6 MPC signing loop and a plain local key
//!   produce) into the 65-byte `r ‖ s ‖ v` Ethereum signature
//!   `SimpleAccount._validateSignature` expects, by brute-forcing the recovery
//!   id.

use alloy::primitives::{Address, Bytes, U256};
use alloy::sol_types::SolCall as _;
use anyhow::Context as _;
use fedimint_usdt_common::user_op::UnsignedUserOp;
use fedimint_usdt_common::{EvmAddress, UsdtAmount, deposit_salt};

alloy::sol! {
    interface ISimpleAccountFactory {
        function createAccount(address owner, uint256 salt) external returns (address);
    }

    interface ISimpleAccount {
        function execute(address dest, uint256 value, bytes calldata func) external;
    }

    interface IERC20Transfer {
        function transfer(address to, uint256 amount) external returns (bool);
    }
}

/// Conservative, static gas bounds for a v0.7 `UserOp`. Gas *estimation*
/// (an `eth_estimateUserOperationGas`-style adapter call) is explicitly
/// deferred to Phase 8 (see the Phase-7 plan's Task 4 section); these are
/// fixed, deliberately generous constants for a known op shape instead.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GasBounds {
    /// Gas allotted to `validateUserOp` PLUS (when `initCode` is non-empty)
    /// the account-creation call itself -- the CREATE2 `ERC1967Proxy` deploy
    /// and its `initialize` call are charged against this limit, not
    /// `call_gas_limit`.
    pub verification_gas_limit: u128,
    /// Gas allotted to the `callData` execution (`SimpleAccount.execute`
    /// wrapping an ERC-20 `transfer`).
    pub call_gas_limit: u128,
    /// Gas the `EntryPoint` credits to the bundler/broadcaster for
    /// off-chain overhead (calldata cost, signature verification setup,
    /// etc.) not otherwise metered.
    pub pre_verification_gas: u128,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
}

impl GasBounds {
    /// Sized for THIS module's specific deploy-and-sweep op shape (one
    /// `ERC1967Proxy` CREATE2 deploy + `SimpleAccount.initialize` + one
    /// `execute`-wrapped ERC-20 `transfer`) on a devnet/anvil-class chain.
    /// Not a general-purpose default -- a real deployment with a different
    /// paymaster/call shape should size its own bounds. `fedimint-usdt-tests`'
    /// `user_op_isolation.rs` acceptance test submits a real op against these
    /// exact bounds on `anvil` and confirms it succeeds end to end, which is
    /// this constant's actual validation (no gas-estimation tooling backs
    /// these numbers -- see this task's gas *estimation* deferral to Phase
    /// 8). Reasoning behind each value:
    /// - `verification_gas_limit = 500_000`: covers `ERC1967Proxy` constructor
    ///   + `SimpleAccount.initialize` + `validateUserOp`'s own `ECDSA.recover`.
    /// - `call_gas_limit = 200_000`: one `execute` dispatch wrapping one ERC-20
    ///   `transfer` (well under typical ERC-20 transfer costs of ~50-65k,
    ///   doubled for `execute`'s own dispatch overhead).
    /// - `pre_verification_gas = 100_000`: generous fixed overhead allowance;
    ///   real bundlers compute this from calldata length, this task does not.
    /// - `max_priority_fee_per_gas = 1.5 gwei`, `max_fee_per_gas = 30 gwei`:
    ///   comfortably above `anvil`'s default ~1 gwei base fee.
    pub const DEPLOY_AND_SWEEP_DEVNET: GasBounds = GasBounds {
        verification_gas_limit: 500_000,
        call_gas_limit: 200_000,
        pre_verification_gas: 100_000,
        max_priority_fee_per_gas: 1_500_000_000,
        max_fee_per_gas: 30_000_000_000,
    };
}

/// Parameters for [`build_deploy_and_sweep_userop`], grouped into one struct
/// per this workspace's convention for functions that would otherwise take
/// too many individual parameters.
#[derive(Debug, Clone)]
pub struct DeployAndSweepParams {
    /// The deployed `SimpleAccountFactory` address (this federation's
    /// `UsdtClientConfig::account_factory`).
    pub account_factory: EvmAddress,
    /// The ERC-20 contract this op sweeps (this federation's
    /// `UsdtClientConfig::usdt_contract`).
    pub usdt_contract: EvmAddress,
    /// The counterfactual deposit account being swept -- the op's `sender`.
    /// Callers compute this via `fedimint_usdt_common::derive_deposit_account`
    /// in production (owner = the group-key EOA); the Task 4 isolation
    /// acceptance test instead derives it from a local test key, to isolate
    /// 4337 mechanics from MPC signing.
    pub deposit_account: EvmAddress,
    /// The EOA `owner` the deposit account's `SimpleAccount` was
    /// initialized with (and whose signature `validateUserOp` checks). MUST
    /// be exactly the `owner` [`deposit_account`](Self::deposit_account) was
    /// derived with -- this function does not (cannot, without an RPC call)
    /// verify that itself.
    pub owner: EvmAddress,
    /// The claim key `deposit_account`'s CREATE2 `salt` was derived from
    /// (see `fedimint_usdt_common::deposit_salt`). MUST correspond to the
    /// same claim key `deposit_account` was derived with, for the same
    /// reason as `owner` above.
    pub claim_pk: fedimint_core::secp256k1::PublicKey,
    /// The amount of `usdt_contract` to sweep to `pool`.
    pub amount: UsdtAmount,
    /// The pool account receiving the swept USDT.
    pub pool: EvmAddress,
    /// This op's `EntryPoint` nonce (`getNonce(sender, key=0)`). Fetching
    /// the live value is left to the caller (an adapter RPC call, out of
    /// this pure function's scope) -- for a `SimpleAccount`'s very first op
    /// (deploy-and-sweep), it is always `0`.
    pub nonce: U256,
    /// Whether `initCode` must be populated (the account has no code yet).
    /// Callers decide via `IServerEvmRpc::get_code_len(deposit_account) ==
    /// 0` (or, for a first-ever sweep, simply `true`).
    pub needs_deploy: bool,
    /// Hook for a future (Phase 6/8) token-paymaster's `paymasterAndData`.
    /// Empty for this task: the isolation acceptance test uses
    /// broadcaster-EOA-fronted gas (`handleOps`'s `beneficiary`), matching
    /// the Phase-7 plan's paymaster-economics scope decision.
    pub paymaster_and_data: Vec<u8>,
    pub gas_bounds: GasBounds,
}

/// Builds the [`UnsignedUserOp`] that deploys (if `needs_deploy`) and sweeps
/// `params.deposit_account`'s `params.amount` of `params.usdt_contract` to
/// `params.pool`:
/// - `sender = params.deposit_account`.
/// - `initCode = account_factory ‖ createAccount(owner, salt)` when
///   `needs_deploy` (empty otherwise), `salt` computed identically to
///   `fedimint_usdt_common::derive_deposit_account`'s own salt (via the shared
///   [`deposit_salt`] helper), so a correctly-paired `(deposit_account, owner,
///   claim_pk)` reproduces the exact `initCode` the account's address was
///   derived from.
/// - `callData = SimpleAccount.execute(usdt_contract, 0, USDT.transfer(pool,
///   amount))`.
/// - `paymasterAndData = params.paymaster_and_data` (empty in this task; see
///   [`DeployAndSweepParams::paymaster_and_data`]'s doc comment).
/// - Gas fields from `params.gas_bounds`.
///
/// Pure function: no RPC, no consensus DB. Consensus logic (Phase 7 Task 5)
/// is expected to call this from `(consensus DB, config)` alone, so every
/// guardian builds the byte-identical op.
#[must_use]
pub fn build_deploy_and_sweep_userop(params: DeployAndSweepParams) -> UnsignedUserOp {
    let init_code = if params.needs_deploy {
        let salt = deposit_salt(&params.claim_pk);
        let create_account_calldata = ISimpleAccountFactory::createAccountCall {
            owner: Address::from(params.owner.0),
            salt: U256::from_be_bytes(salt),
        }
        .abi_encode();

        let mut init_code = params.account_factory.0.to_vec();
        init_code.extend_from_slice(&create_account_calldata);
        init_code
    } else {
        Vec::new()
    };

    let transfer_calldata = IERC20Transfer::transferCall {
        to: Address::from(params.pool.0),
        amount: U256::from(params.amount.0),
    }
    .abi_encode();

    let call_data = ISimpleAccount::executeCall {
        dest: Address::from(params.usdt_contract.0),
        value: U256::ZERO,
        func: Bytes::from(transfer_calldata),
    }
    .abi_encode();

    UnsignedUserOp {
        sender: params.deposit_account,
        nonce: params.nonce,
        init_code,
        call_data,
        verification_gas_limit: params.gas_bounds.verification_gas_limit,
        call_gas_limit: params.gas_bounds.call_gas_limit,
        pre_verification_gas: U256::from(params.gas_bounds.pre_verification_gas),
        max_priority_fee_per_gas: params.gas_bounds.max_priority_fee_per_gas,
        max_fee_per_gas: params.gas_bounds.max_fee_per_gas,
        paymaster_and_data: params.paymaster_and_data,
    }
}

/// Decodes the ERC-20 `transfer(to, amount)` amount embedded in a
/// deploy-and-sweep [`UnsignedUserOp`]'s `call_data` (a `SimpleAccount.
/// execute(dest, value, func)` call wrapping an ERC-20 `transfer(to,
/// amount)` -- see [`build_deploy_and_sweep_userop`]).
///
/// Used by the guardian-local `UserOp` confirmation task (Phase 7, Task 5)
/// to derive the `swept` amount for a successful `UserOpConfirmed`
/// observation directly from the already-federation-agreed `op` -- pure
/// function, no RPC call needed for the amount itself (only `success`/
/// `block` come from `IServerEvmRpc::get_user_op_receipt`), so every
/// guardian proposing for the same op independently computes the identical
/// `swept` value once they agree `success`.
///
/// # Errors
///
/// Returns an error if `op.call_data` is not a valid `execute()` call
/// wrapping a valid `transfer()` call (e.g. a future `Withdraw`-purpose op
/// shaped differently -- out of scope for this phase), or if the decoded
/// amount overflows `u64`.
pub fn decode_transfer_amount(op: &UnsignedUserOp) -> anyhow::Result<UsdtAmount> {
    let execute = ISimpleAccount::executeCall::abi_decode(&op.call_data)
        .context("call_data is not a valid execute() call")?;
    let transfer = IERC20Transfer::transferCall::abi_decode(&execute.func)
        .context("execute()'s func arg is not a valid transfer() call")?;
    let amount = u64::try_from(transfer.amount).context("transfer() amount overflows u64")?;

    Ok(UsdtAmount(amount))
}

/// Assembles a 65-byte Ethereum `r ‖ s ‖ v` signature from a compact,
/// low-S-normalized `(r, s)` (the shape both `fedimint_threshold_ecdsa`'s
/// MPC signing loop and a plain `secp256k1` ECDSA sign produce) over
/// `signed_digest`, by brute-forcing the recovery id `v ∈ {0, 1}` (encoded
/// as the 65th byte `27`/`28`, "Electrum" notation) -- picking whichever
/// recovers to `owner`.
///
/// `signed_digest` must be the EXACT digest that was signed -- for a
/// `SimpleAccount` v0.7 `UserOp`, that is
/// `fedimint_usdt_common::user_op::eth_signed_message_hash(user_op_hash)`
/// (the EIP-191-wrapped digest `_validateSignature` actually recovers
/// against), **not** the raw `user_op_hash`.
///
/// # Errors
///
/// Returns an error if `compact_rs` is not a valid compact secp256k1
/// signature, or if NEITHER recovery id recovers to `owner` (e.g. `owner`
/// does not match the key that produced `compact_rs`, or `signed_digest`
/// does not match what was actually signed).
pub fn assemble_eth_signature(
    compact_rs: [u8; 64],
    signed_digest: [u8; 32],
    owner: EvmAddress,
) -> anyhow::Result<[u8; 65]> {
    use fedimint_core::secp256k1;

    let message = secp256k1::Message::from_digest(signed_digest);

    for recovery_id in 0..2u8 {
        // `0` and `1` are always valid secp256k1 recovery ids, but a
        // `let ... else { continue }` (rather than `.expect`) keeps this
        // function panic-free regardless.
        let Ok(recid) = secp256k1::ecdsa::RecoveryId::from_i32(i32::from(recovery_id)) else {
            continue;
        };
        let Ok(recoverable) =
            secp256k1::ecdsa::RecoverableSignature::from_compact(&compact_rs, recid)
        else {
            continue;
        };
        let Ok(recovered_pk) = recoverable.recover(&message) else {
            continue;
        };

        if fedimint_usdt_common::evm_address(&recovered_pk) == owner {
            let mut signature = [0u8; 65];
            signature[..64].copy_from_slice(&compact_rs);
            signature[64] = 27 + recovery_id;
            return Ok(signature);
        }
    }

    anyhow::bail!(
        "neither recovery id (0 nor 1) for the given (r, s) recovers to owner {owner} over the \
         given digest -- either the signature was not produced by owner's key, or \
         signed_digest does not match the digest that was actually signed"
    );
}

#[cfg(test)]
mod tests {
    use alloy::sol_types::SolCall as _;
    use fedimint_core::secp256k1;
    use fedimint_usdt_common::user_op::eth_signed_message_hash;

    use super::*;

    /// Deterministic, distinct-from-each-other test secp256k1 keys, mirroring
    /// this crate's other `test_pubkey`-style helpers.
    fn test_secret_key(byte: u8) -> secp256k1::SecretKey {
        secp256k1::SecretKey::from_slice(&[byte; 32]).expect("nonzero byte is a valid scalar")
    }

    fn sample_params(needs_deploy: bool) -> DeployAndSweepParams {
        let claim_secret = test_secret_key(0x07);
        let claim_pk = claim_secret.public_key(secp256k1::SECP256K1);
        let owner_secret = test_secret_key(0x09);
        let owner_pk = owner_secret.public_key(secp256k1::SECP256K1);
        let owner = fedimint_usdt_common::evm_address(&owner_pk);

        let account_factory = EvmAddress([0xaa; 20]);
        let simple_account_impl = EvmAddress([0xbb; 20]);
        let deposit_account = fedimint_usdt_common::derive_deposit_account(
            &owner_pk,
            account_factory,
            simple_account_impl,
            &claim_pk,
        );

        DeployAndSweepParams {
            account_factory,
            usdt_contract: EvmAddress([0xcc; 20]),
            deposit_account,
            owner,
            claim_pk,
            amount: UsdtAmount(1_500_000),
            pool: EvmAddress([0xdd; 20]),
            nonce: U256::ZERO,
            needs_deploy,
            paymaster_and_data: Vec::new(),
            gas_bounds: GasBounds::DEPLOY_AND_SWEEP_DEVNET,
        }
    }

    #[test]
    fn builder_selectors_match_the_real_erc20_transfer_selector() {
        // `transfer(address,uint256)`'s selector is a well-known constant
        // (`0xa9059cbb`); cross-check the `sol!`-generated one against it
        // directly, independent of `alloy_primitives::keccak256`, so this
        // test cannot pass merely because both sides share a buggy keccak
        // call.
        assert_eq!(
            IERC20Transfer::transferCall::SELECTOR,
            [0xa9, 0x05, 0x9c, 0xbb]
        );
    }

    #[test]
    fn builder_selectors_are_internally_consistent_with_keccak() {
        // Cross-checks every selector this module relies on against a
        // straight `keccak256(signature)[..4]` computation, independent of
        // `alloy_sol_types`'s own selector derivation.
        for (signature, selector) in [
            (
                "createAccount(address,uint256)",
                ISimpleAccountFactory::createAccountCall::SELECTOR,
            ),
            (
                "execute(address,uint256,bytes)",
                ISimpleAccount::executeCall::SELECTOR,
            ),
            (
                "transfer(address,uint256)",
                IERC20Transfer::transferCall::SELECTOR,
            ),
        ] {
            let hash = alloy::primitives::keccak256(signature.as_bytes());
            assert_eq!(
                &hash[..4],
                &selector[..],
                "selector mismatch for {signature}"
            );
        }
    }

    #[test]
    fn build_with_needs_deploy_populates_init_code_with_the_factory_prefix() {
        let params = sample_params(true);
        let account_factory = params.account_factory;
        let op = build_deploy_and_sweep_userop(params);

        assert!(!op.init_code.is_empty());
        assert_eq!(&op.init_code[..20], &account_factory.0[..]);
        assert_eq!(
            &op.init_code[20..24],
            &ISimpleAccountFactory::createAccountCall::SELECTOR[..]
        );
    }

    #[test]
    fn build_without_needs_deploy_has_empty_init_code() {
        let op = build_deploy_and_sweep_userop(sample_params(false));
        assert!(op.init_code.is_empty());
    }

    #[test]
    fn build_call_data_is_an_execute_call_wrapping_a_transfer_call() {
        let params = sample_params(false);
        let (usdt_contract, pool, amount) = (params.usdt_contract, params.pool, params.amount);
        let op = build_deploy_and_sweep_userop(params);

        assert_eq!(
            &op.call_data[..4],
            &ISimpleAccount::executeCall::SELECTOR[..]
        );
        let decoded = ISimpleAccount::executeCall::abi_decode(&op.call_data)
            .expect("build_deploy_and_sweep_userop must produce valid execute() calldata");
        assert_eq!(decoded.dest, Address::from(usdt_contract.0));
        assert_eq!(decoded.value, U256::ZERO);

        assert_eq!(
            &decoded.func[..4],
            &IERC20Transfer::transferCall::SELECTOR[..]
        );
        let inner = IERC20Transfer::transferCall::abi_decode(&decoded.func)
            .expect("execute()'s func arg must be valid transfer() calldata");
        assert_eq!(inner.to, Address::from(pool.0));
        assert_eq!(inner.amount, U256::from(amount.0));
    }

    #[test]
    fn build_sender_is_the_deposit_account() {
        let params = sample_params(true);
        let deposit_account = params.deposit_account;
        let op = build_deploy_and_sweep_userop(params);
        assert_eq!(op.sender, deposit_account);
    }

    #[test]
    fn assemble_eth_signature_round_trips_a_known_key() {
        let secp = secp256k1::Secp256k1::new();
        let sk = test_secret_key(0x42);
        let pk = sk.public_key(&secp);
        let owner = fedimint_usdt_common::evm_address(&pk);

        let user_op_hash = [0x55u8; 32];
        let digest = eth_signed_message_hash(user_op_hash);
        let message = secp256k1::Message::from_digest(digest);

        let recoverable = secp.sign_ecdsa_recoverable(&message, &sk);
        let (_recid, compact_rs) = recoverable.serialize_compact();

        let signature = assemble_eth_signature(compact_rs, digest, owner)
            .expect("a signature produced by owner's key must assemble successfully");

        assert_eq!(signature.len(), 65);
        assert_eq!(&signature[..64], &compact_rs[..]);
        assert!(signature[64] == 27 || signature[64] == 28);

        // Round-trip: recovering with the assembled `v` against the same
        // digest must yield `owner` again.
        let recid = secp256k1::ecdsa::RecoveryId::from_i32(i32::from(signature[64] - 27))
            .expect("27/28 map to valid recovery ids 0/1");
        let recovered_sig =
            secp256k1::ecdsa::RecoverableSignature::from_compact(&compact_rs, recid)
                .expect("compact_rs + a valid recid must parse");
        let recovered_pk = recovered_sig
            .recover(&message)
            .expect("recovery must succeed for the signature's own digest");
        assert_eq!(fedimint_usdt_common::evm_address(&recovered_pk), owner);
    }

    #[test]
    fn assemble_eth_signature_rejects_a_signature_from_a_different_key() {
        let secp = secp256k1::Secp256k1::new();
        let signer_sk = test_secret_key(0x11);
        let wrong_owner_pk = test_secret_key(0x22).public_key(&secp);
        let wrong_owner = fedimint_usdt_common::evm_address(&wrong_owner_pk);

        let digest = eth_signed_message_hash([0x66u8; 32]);
        let message = secp256k1::Message::from_digest(digest);
        let recoverable = secp.sign_ecdsa_recoverable(&message, &signer_sk);
        let (_recid, compact_rs) = recoverable.serialize_compact();

        let err = assemble_eth_signature(compact_rs, digest, wrong_owner)
            .expect_err("a signature from a different key must not assemble against wrong_owner");
        assert!(err.to_string().contains("neither recovery id"));
    }

    #[test]
    fn assemble_eth_signature_rejects_a_mismatched_digest() {
        let secp = secp256k1::Secp256k1::new();
        let sk = test_secret_key(0x33);
        let pk = sk.public_key(&secp);
        let owner = fedimint_usdt_common::evm_address(&pk);

        let signed_digest = eth_signed_message_hash([0x77u8; 32]);
        let message = secp256k1::Message::from_digest(signed_digest);
        let recoverable = secp.sign_ecdsa_recoverable(&message, &sk);
        let (_recid, compact_rs) = recoverable.serialize_compact();

        // Assemble against a DIFFERENT digest than what was actually signed.
        let other_digest = eth_signed_message_hash([0x88u8; 32]);
        let err = assemble_eth_signature(compact_rs, other_digest, owner)
            .expect_err("a mismatched digest must not recover to owner");
        assert!(err.to_string().contains("neither recovery id"));
    }
}
