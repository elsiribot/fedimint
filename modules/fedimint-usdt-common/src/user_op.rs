//! ERC-4337 v0.7 `PackedUserOperation` types, packing, and `userOpHash`
//! (Phase 7 Task 3).
//!
//! Everything here is a pure function of its arguments (no RPC, no
//! wall-clock) so both the client (wasm) and every guardian compute
//! bit-identical results, matching the determinism discipline the rest of
//! this crate follows (see [`crate::derive_deposit_account`]).
//!
//! The hash formula is `EntryPoint` v0.7's `getUserOpHash` (**not** v0.8's
//! EIP-712 variant): `UserOperationLib.hash`/`.encode` from
//! `@account-abstraction/contracts@0.7.0`. It is pinned against the real
//! on-chain `EntryPoint.getUserOpHash` by
//! `fedimint-usdt-tests/tests/user_op_hash.rs`'s
//! `user_op_hash_matches_entry_point_get_user_op_hash` test — this module's
//! doc comments describe the *intended* formula, but that anvil test is the
//! actual source of truth.

use alloy_primitives::{Address, Bytes, FixedBytes, U256, keccak256};
use alloy_sol_types::SolValue as _;
use fedimint_core::encoding::{Decodable, DecodeError, Encodable};
use fedimint_core::module::registry::ModuleDecoderRegistry;
use serde::{Deserialize, Serialize};

use crate::{EvmAddress, UsdtAmount};

alloy_sol_types::sol! {
    // Applies to every item in this macro invocation (must be the block's
    // own inner attribute, not a per-item one): gets us
    // `Debug`/`PartialEq`/`Eq`/`Hash` on `PackedUserOperation` in addition
    // to the macro's default `Clone`, for tests and logging.
    #![sol(all_derives)]

    /// The v0.7 on-chain `PackedUserOperation` struct
    /// (`@account-abstraction/contracts@0.7.0`'s
    /// `interfaces/PackedUserOperation.sol`).
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
}

/// Packs `(hi, lo)` into a big-endian 32-byte word: the high 16 bytes hold
/// `hi`, the low 16 bytes hold `lo`. Mirrors `PackedUserOperation`'s
/// `accountGasLimits`/`gasFees` bit-packing
/// (`UserOperationLib.unpackVerificationGasLimit`/`unpackCallGasLimit`/
/// `unpackMaxPriorityFeePerGas`/`unpackMaxFeePerGas`: each reads one 128-bit
/// half of a `bytes32` field).
fn pack_u128_hi_lo(hi: u128, lo: u128) -> FixedBytes<32> {
    let mut bytes = [0u8; 32];
    bytes[..16].copy_from_slice(&hi.to_be_bytes());
    bytes[16..].copy_from_slice(&lo.to_be_bytes());
    FixedBytes::from(bytes)
}

/// Inverse of [`pack_u128_hi_lo`]. Not used by production code (nothing
/// unpacks a [`PackedUserOperation`] back into an [`UnsignedUserOp`] yet —
/// this crate only ever builds ops in the unpacked direction), but exercises
/// the packing round-trip in this module's unit tests below.
#[cfg(test)]
fn unpack_u128_hi_lo(packed: FixedBytes<32>) -> (u128, u128) {
    let hi = u128::from_be_bytes(
        packed[..16]
            .try_into()
            .expect("first 16 bytes of a 32-byte array is always a valid 16-byte slice"),
    );
    let lo = u128::from_be_bytes(
        packed[16..]
            .try_into()
            .expect("last 16 bytes of a 32-byte array is always a valid 16-byte slice"),
    );
    (hi, lo)
}

/// An ergonomic, unsigned, UNPACKED-gas-fields view of a v0.7 `UserOp`.
///
/// This is the type consensus logic (Task 5) builds and feeds to the
/// Phase-6 signing loop over its [`user_op_hash`]; [`Self::pack`] produces
/// the on-chain [`PackedUserOperation`] shape (with an empty `signature`).
///
/// `nonce`/`pre_verification_gas` are kept as `alloy_primitives::U256`
/// (matching the on-chain `uint256` width) rather than a smaller Rust int,
/// since `EntryPoint` never bounds them below 256 bits (even though this
/// module's own nonce/gas values are always far smaller in practice).
/// `verification_gas_limit`/`call_gas_limit`/`max_priority_fee_per_gas`/
/// `max_fee_per_gas` are `u128`, matching the 128-bit halves
/// `accountGasLimits`/`gasFees` actually pack.
///
/// `Encodable`/`Decodable` are hand-written (see the `impl` blocks below)
/// rather than `#[derive]`d: `fedimint_core` provides no
/// `Encodable`/`Decodable` impl for `u128` or for foreign types like
/// `alloy_primitives::U256` (and the orphan rule blocks adding one from this
/// crate), so each of those fields is encoded/decoded as fixed-width
/// big-endian bytes directly instead of delegating to a per-field trait
/// call. `EvmAddress`/`Vec<u8>` fields still delegate normally.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsignedUserOp {
    pub sender: EvmAddress,
    pub nonce: U256,
    pub init_code: Vec<u8>,
    pub call_data: Vec<u8>,
    pub verification_gas_limit: u128,
    pub call_gas_limit: u128,
    pub pre_verification_gas: U256,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub paymaster_and_data: Vec<u8>,
}

impl UnsignedUserOp {
    /// Packs this op into the on-chain [`PackedUserOperation`] shape:
    /// `accountGasLimits = hi128(verification_gas_limit) ‖
    /// lo128(call_gas_limit)`, `gasFees = hi128(max_priority_fee_per_gas) ‖
    /// lo128(max_fee_per_gas)` (see [`pack_u128_hi_lo`]). `signature` is
    /// always empty here — an unsigned op has none; see
    /// [`SignedUserOp::pack`] for the signed form.
    #[must_use]
    pub fn pack(&self) -> PackedUserOperation {
        PackedUserOperation {
            sender: Address::from(self.sender.0),
            nonce: self.nonce,
            initCode: Bytes::from(self.init_code.clone()),
            callData: Bytes::from(self.call_data.clone()),
            accountGasLimits: pack_u128_hi_lo(self.verification_gas_limit, self.call_gas_limit),
            preVerificationGas: self.pre_verification_gas,
            gasFees: pack_u128_hi_lo(self.max_priority_fee_per_gas, self.max_fee_per_gas),
            paymasterAndData: Bytes::from(self.paymaster_and_data.clone()),
            signature: Bytes::new(),
        }
    }
}

impl Encodable for UnsignedUserOp {
    fn consensus_encode<W: std::io::Write>(&self, writer: &mut W) -> Result<(), std::io::Error> {
        self.sender.consensus_encode(writer)?;
        writer.write_all(&self.nonce.to_be_bytes::<32>())?;
        self.init_code.consensus_encode(writer)?;
        self.call_data.consensus_encode(writer)?;
        writer.write_all(&self.verification_gas_limit.to_be_bytes())?;
        writer.write_all(&self.call_gas_limit.to_be_bytes())?;
        writer.write_all(&self.pre_verification_gas.to_be_bytes::<32>())?;
        writer.write_all(&self.max_priority_fee_per_gas.to_be_bytes())?;
        writer.write_all(&self.max_fee_per_gas.to_be_bytes())?;
        self.paymaster_and_data.consensus_encode(writer)?;
        Ok(())
    }
}

impl Decodable for UnsignedUserOp {
    fn consensus_decode_partial<D: std::io::Read>(
        d: &mut D,
        modules: &ModuleDecoderRegistry,
    ) -> Result<Self, DecodeError> {
        let sender = EvmAddress::consensus_decode_partial(d, modules)?;

        let mut nonce_bytes = [0u8; 32];
        d.read_exact(&mut nonce_bytes)
            .map_err(DecodeError::from_err)?;
        let nonce = U256::from_be_bytes(nonce_bytes);

        let init_code = Vec::<u8>::consensus_decode_partial(d, modules)?;
        let call_data = Vec::<u8>::consensus_decode_partial(d, modules)?;

        let mut verification_gas_limit_bytes = [0u8; 16];
        d.read_exact(&mut verification_gas_limit_bytes)
            .map_err(DecodeError::from_err)?;
        let verification_gas_limit = u128::from_be_bytes(verification_gas_limit_bytes);

        let mut call_gas_limit_bytes = [0u8; 16];
        d.read_exact(&mut call_gas_limit_bytes)
            .map_err(DecodeError::from_err)?;
        let call_gas_limit = u128::from_be_bytes(call_gas_limit_bytes);

        let mut pre_verification_gas_bytes = [0u8; 32];
        d.read_exact(&mut pre_verification_gas_bytes)
            .map_err(DecodeError::from_err)?;
        let pre_verification_gas = U256::from_be_bytes(pre_verification_gas_bytes);

        let mut max_priority_fee_per_gas_bytes = [0u8; 16];
        d.read_exact(&mut max_priority_fee_per_gas_bytes)
            .map_err(DecodeError::from_err)?;
        let max_priority_fee_per_gas = u128::from_be_bytes(max_priority_fee_per_gas_bytes);

        let mut max_fee_per_gas_bytes = [0u8; 16];
        d.read_exact(&mut max_fee_per_gas_bytes)
            .map_err(DecodeError::from_err)?;
        let max_fee_per_gas = u128::from_be_bytes(max_fee_per_gas_bytes);

        let paymaster_and_data = Vec::<u8>::consensus_decode_partial(d, modules)?;

        Ok(Self {
            sender,
            nonce,
            init_code,
            call_data,
            verification_gas_limit,
            call_gas_limit,
            pre_verification_gas,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            paymaster_and_data,
        })
    }
}

/// A signed v0.7 `UserOp`: the unsigned op plus its 65-byte `r‖s‖v` Ethereum
/// signature over [`user_op_hash`] (assembled from the Phase-6 MPC signature
/// in a later task; this type only carries the result).
///
/// `Encodable`/`Decodable`/`Serialize`/`Deserialize` are `#[derive]`d
/// (rather than hand-written like [`UnsignedUserOp`]'s) because both field
/// types (`UnsignedUserOp`, `Vec<u8>`) already implement those traits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Encodable, Decodable)]
pub struct SignedUserOp {
    pub unsigned: UnsignedUserOp,
    pub signature: Vec<u8>,
}

impl SignedUserOp {
    /// Packs this op into the on-chain [`PackedUserOperation`] shape, with
    /// `signature` filled in (unlike [`UnsignedUserOp::pack`]'s always-empty
    /// one).
    #[must_use]
    pub fn pack(&self) -> PackedUserOperation {
        let mut packed = self.unsigned.pack();
        packed.signature = Bytes::from(self.signature.clone());
        packed
    }
}

/// Computes the `EntryPoint` v0.7 `userOpHash` for `op`, as if submitted to
/// `entry_point` on chain `chain_id`:
///
/// ```text
/// inner = keccak256(abi.encode(
///     sender, nonce, keccak256(initCode), keccak256(callData),
///     accountGasLimits, preVerificationGas, gasFees,
///     keccak256(paymasterAndData),
/// ))
/// userOpHash = keccak256(abi.encode(inner, entry_point, chain_id))
/// ```
///
/// This is `UserOperationLib.hash`/`.encode` composed with
/// `EntryPoint.getUserOpHash`'s own outer `abi.encode(userOp.hash(),
/// address(this), block.chainid)` — v0.7's formula, **not** v0.8's EIP-712
/// one. Deliberately excludes `signature` (matching the on-chain function,
/// which takes the digest guardians sign *before* a signature exists).
///
/// Pure function, no RPC — both client and every guardian call this exact
/// function so the digest they sign is bit-for-bit identical. Self-verified
/// against a real anvil-deployed `EntryPoint.getUserOpHash` by
/// `fedimint-usdt-tests/tests/user_op_hash.rs`.
#[must_use]
pub fn user_op_hash(op: &UnsignedUserOp, entry_point: EvmAddress, chain_id: u64) -> [u8; 32] {
    let packed = op.pack();

    // `(address, uint256, bytes32, bytes32, bytes32, uint256, bytes32,
    // bytes32)`: the three on-chain `bytes` fields (`initCode`, `callData`,
    // `paymasterAndData`) are replaced by their own `keccak256`, and
    // `accountGasLimits`/`gasFees` -- `bytes32` on-chain but read as
    // `uint256` in `UserOperationLib.encode` -- are passed through as
    // `bytes32`/`FixedBytes<32>`, which ABI-encodes to the identical 32-byte
    // word as `uint256` would (both are a single left-padded/verbatim word).
    let inner_preimage = (
        packed.sender,
        packed.nonce,
        keccak256(packed.initCode.as_ref()),
        keccak256(packed.callData.as_ref()),
        packed.accountGasLimits,
        packed.preVerificationGas,
        packed.gasFees,
        keccak256(packed.paymasterAndData.as_ref()),
    )
        .abi_encode_params();
    let inner_hash = keccak256(inner_preimage);

    let outer_preimage = (
        inner_hash,
        Address::from(entry_point.0),
        U256::from(chain_id),
    )
        .abi_encode_params();

    keccak256(outer_preimage).0
}

/// EIP-191's `toEthSignedMessageHash`: `keccak256("\x19Ethereum Signed
/// Message:\n32" ‖ user_op_hash)`.
///
/// This is the digest `SimpleAccount` v0.7's `_validateSignature` actually
/// checks a `UserOp`'s `signature` against -- **not** the raw [`user_op_hash`]
/// -- via `MessageHashUtils.toEthSignedMessageHash(userOpHash)` followed by
/// `ECDSA.recover(hash, userOp.signature) == owner`
/// (`@account-abstraction/contracts@0.7.0`'s `samples/SimpleAccount.sol`).
/// So the Phase-6 MPC signing loop must sign *this* wrapped digest, not
/// `user_op_hash` directly, and
/// `fedimint_usdt_server::user_op::assemble_eth_signature` (Phase 7 Task 4)
/// must recover against it too.
///
/// Pure function, no RPC -- wasm-safe, callable from both client and every
/// guardian.
#[must_use]
pub fn eth_signed_message_hash(user_op_hash: [u8; 32]) -> [u8; 32] {
    const EIP_191_PREFIX: &[u8] = b"\x19Ethereum Signed Message:\n32";

    let mut preimage = Vec::with_capacity(EIP_191_PREFIX.len() + 32);
    preimage.extend_from_slice(EIP_191_PREFIX);
    preimage.extend_from_slice(&user_op_hash);

    keccak256(preimage).0
}

/// The outcome of a submitted [`SignedUserOp`], read back from the
/// `EntryPoint`'s `UserOperationEvent` log (Phase 7 Task 4,
/// `IServerEvmRpc::get_user_op_receipt`).
///
/// Plain data (no RPC/provider surface) so it can live in this WASM-safe
/// crate even though only the server ever constructs one.
///
/// `actual_gas_cost_wei` (renamed from `actual_cost_usdt`, misc #18 / finding
/// 22's doc facet -- the old name falsely implied a USDT-denominated value)
/// is `UserOperationEvent.actualGasCost` **verbatim, in wei**. No token
/// paymaster is used: `AlloyEvmRpc::submit_user_ops` calls `handleOps` with
/// an empty `paymasterAndData` (broadcaster-EOA-fronted ETH gas; see
/// `security-review/22-low-broadcaster-eth-funding-no-reimbursement.md`), so
/// no USDT is charged for gas in this flow at all -- deposit/withdrawal fees
/// are collected separately, in USDT, by `process_input`/`process_output`,
/// with no protocol-level conversion back into ETH reimbursement for the
/// broadcaster. `UsdtAmount` is reused here only because it is a convenient
/// `u64` newtype; the unit carried is wei, not USDT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserOpReceipt {
    /// Whether the `UserOp`'s `callData` execution succeeded (the
    /// `UserOperationEvent.success` flag). `false` means the op was
    /// validated and included on-chain (so it consumed its nonce) but its
    /// `callData` call reverted -- distinct from the op never landing at
    /// all, which is `IServerEvmRpc::get_user_op_receipt` returning `None`.
    pub success: bool,
    /// The block the `UserOperationEvent` was emitted in.
    pub block: u64,
    /// See this struct's doc comment: the raw `actualGasCost` **wei**
    /// value (`UsdtAmount` reused only as a convenient `u64` newtype -- this
    /// is NOT a USDT amount).
    pub actual_gas_cost_wei: UsdtAmount,
}

#[cfg(test)]
mod tests {
    use fedimint_core::encoding::{Decodable, Encodable};
    use fedimint_core::module::registry::ModuleDecoderRegistry;

    use super::*;

    /// A representative, non-trivially-shaped (non-empty `initCode` /
    /// `callData` / `paymasterAndData`) op for the packing/round-trip unit
    /// tests below. Distinct, non-symmetric field values so a bug that
    /// swaps two same-width fields (e.g. `verification_gas_limit` /
    /// `call_gas_limit`) would be caught.
    fn sample_op() -> UnsignedUserOp {
        UnsignedUserOp {
            sender: EvmAddress([0x11; 20]),
            nonce: U256::from(7u64),
            init_code: vec![0xde, 0xad, 0xbe, 0xef],
            call_data: vec![0xca, 0xfe, 0xba, 0xbe, 0x01],
            verification_gas_limit: 100_000,
            call_gas_limit: 200_000,
            pre_verification_gas: U256::from(50_000u64),
            max_priority_fee_per_gas: 1_500_000_000,
            max_fee_per_gas: 30_000_000_000,
            paymaster_and_data: vec![0x01, 0x02, 0x03],
        }
    }

    #[test]
    fn pack_u128_hi_lo_round_trips() {
        let hi = 0x1122_3344_5566_7788_99aa_bbcc_ddee_ff00_u128;
        let lo = 0x0011_2233_4455_6677_8899_aabb_ccdd_eeff_u128;

        let packed = pack_u128_hi_lo(hi, lo);
        assert_eq!(packed.len(), 32);
        assert_eq!(&packed[..16], &hi.to_be_bytes());
        assert_eq!(&packed[16..], &lo.to_be_bytes());

        let (hi_back, lo_back) = unpack_u128_hi_lo(packed);
        assert_eq!((hi, lo), (hi_back, lo_back));
    }

    #[test]
    fn pack_u128_hi_lo_zero_and_max_round_trip() {
        for (hi, lo) in [
            (0u128, 0u128),
            (u128::MAX, u128::MAX),
            (u128::MAX, 0),
            (0, u128::MAX),
        ] {
            let (hi_back, lo_back) = unpack_u128_hi_lo(pack_u128_hi_lo(hi, lo));
            assert_eq!((hi, lo), (hi_back, lo_back));
        }
    }

    #[test]
    fn pack_splits_account_gas_limits_and_gas_fees_into_the_right_halves() {
        let op = sample_op();
        let packed = op.pack();

        let (verification, call) = unpack_u128_hi_lo(packed.accountGasLimits);
        assert_eq!(verification, op.verification_gas_limit);
        assert_eq!(call, op.call_gas_limit);

        let (priority, max_fee) = unpack_u128_hi_lo(packed.gasFees);
        assert_eq!(priority, op.max_priority_fee_per_gas);
        assert_eq!(max_fee, op.max_fee_per_gas);
    }

    #[test]
    fn pack_carries_over_sender_nonce_and_calldata_fields_unpacked() {
        let op = sample_op();
        let packed = op.pack();

        assert_eq!(packed.sender, Address::from(op.sender.0));
        assert_eq!(packed.nonce, op.nonce);
        assert_eq!(packed.initCode.as_ref(), op.init_code.as_slice());
        assert_eq!(packed.callData.as_ref(), op.call_data.as_slice());
        assert_eq!(packed.preVerificationGas, op.pre_verification_gas);
        assert_eq!(
            packed.paymasterAndData.as_ref(),
            op.paymaster_and_data.as_slice()
        );
    }

    #[test]
    fn pack_from_unsigned_op_has_empty_signature() {
        assert!(sample_op().pack().signature.is_empty());
    }

    #[test]
    fn signed_user_op_pack_fills_in_the_signature() {
        let unsigned = sample_op();
        let signature = vec![0xaa; 65];
        let signed = SignedUserOp {
            unsigned: unsigned.clone(),
            signature: signature.clone(),
        };

        let packed = signed.pack();
        assert_eq!(packed.signature.as_ref(), signature.as_slice());
        // Everything else matches the unsigned pack.
        let mut unsigned_packed = unsigned.pack();
        unsigned_packed.signature = packed.signature.clone();
        assert_eq!(packed, unsigned_packed);
    }

    #[test]
    fn unsigned_user_op_round_trips_through_consensus_encoding() {
        let op = sample_op();
        let bytes = op.consensus_encode_to_vec();
        let decoded =
            UnsignedUserOp::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
                .expect("UnsignedUserOp should decode what it just encoded");

        assert_eq!(op, decoded);
    }

    #[test]
    fn unsigned_user_op_with_empty_variable_fields_round_trips() {
        let op = UnsignedUserOp {
            sender: EvmAddress([0u8; 20]),
            nonce: U256::ZERO,
            init_code: vec![],
            call_data: vec![],
            verification_gas_limit: 0,
            call_gas_limit: 0,
            pre_verification_gas: U256::ZERO,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 0,
            paymaster_and_data: vec![],
        };
        let bytes = op.consensus_encode_to_vec();
        let decoded = UnsignedUserOp::consensus_decode_whole(
            &bytes,
            &ModuleDecoderRegistry::default(),
        )
        .expect(
            "UnsignedUserOp with empty variable-length fields should decode what it just encoded",
        );

        assert_eq!(op, decoded);
    }

    #[test]
    fn unsigned_user_op_with_max_u256_fields_round_trips() {
        let mut op = sample_op();
        op.nonce = U256::MAX;
        op.pre_verification_gas = U256::MAX;
        op.verification_gas_limit = u128::MAX;
        op.call_gas_limit = u128::MAX;
        op.max_priority_fee_per_gas = u128::MAX;
        op.max_fee_per_gas = u128::MAX;

        let bytes = op.consensus_encode_to_vec();
        let decoded =
            UnsignedUserOp::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
                .expect(
                    "UnsignedUserOp with maximal field values should decode what it just encoded",
                );

        assert_eq!(op, decoded);
    }

    #[test]
    fn signed_user_op_round_trips_through_consensus_encoding() {
        let signed = SignedUserOp {
            unsigned: sample_op(),
            signature: vec![0xbb; 65],
        };
        let bytes = signed.consensus_encode_to_vec();
        let decoded =
            SignedUserOp::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
                .expect("SignedUserOp should decode what it just encoded");

        assert_eq!(signed, decoded);
    }

    #[test]
    fn user_op_hash_is_deterministic_and_sensitive_to_entry_point_and_chain_id() {
        let op = sample_op();
        let entry_point = EvmAddress([0x22; 20]);

        assert_eq!(
            user_op_hash(&op, entry_point, 31337),
            user_op_hash(&op, entry_point, 31337)
        );
        assert_ne!(
            user_op_hash(&op, entry_point, 31337),
            user_op_hash(&op, entry_point, 1)
        );
        let other_entry_point = EvmAddress([0x33; 20]);
        assert_ne!(
            user_op_hash(&op, entry_point, 31337),
            user_op_hash(&op, other_entry_point, 31337)
        );
    }

    #[test]
    fn user_op_hash_excludes_signature() {
        // `user_op_hash` takes an `UnsignedUserOp` (no signature field to
        // begin with), so two ops that only differ in what their eventual
        // `SignedUserOp::signature` would be hash identically. This test
        // exists to document that invariant explicitly (mirrored by the
        // on-chain `getUserOpHash`, which is called before any signature is
        // attached).
        let op = sample_op();
        let entry_point = EvmAddress([0x22; 20]);

        let signed_a = SignedUserOp {
            unsigned: op.clone(),
            signature: vec![0x01; 65],
        };
        let signed_b = SignedUserOp {
            unsigned: op.clone(),
            signature: vec![0x02; 65],
        };

        assert_eq!(
            user_op_hash(&signed_a.unsigned, entry_point, 31337),
            user_op_hash(&signed_b.unsigned, entry_point, 31337)
        );
    }

    #[test]
    fn eth_signed_message_hash_matches_eip_191_by_hand() {
        let user_op_hash = [0x77u8; 32];

        let mut expected_preimage = b"\x19Ethereum Signed Message:\n32".to_vec();
        expected_preimage.extend_from_slice(&user_op_hash);
        let expected = keccak256(expected_preimage).0;

        assert_eq!(eth_signed_message_hash(user_op_hash), expected);
    }

    #[test]
    fn eth_signed_message_hash_is_deterministic_and_input_sensitive() {
        assert_eq!(
            eth_signed_message_hash([0x11; 32]),
            eth_signed_message_hash([0x11; 32])
        );
        assert_ne!(
            eth_signed_message_hash([0x11; 32]),
            eth_signed_message_hash([0x22; 32])
        );
        // The wrapped digest must differ from the raw input (i.e. the
        // EIP-191 prefix must actually be mixed in, not a no-op).
        assert_ne!(eth_signed_message_hash([0x33; 32]), [0x33; 32]);
    }
}
