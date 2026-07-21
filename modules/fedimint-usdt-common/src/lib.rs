#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use std::fmt;

use anyhow::Context as _;
use config::UsdtClientConfig;
use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{AmountUnit, CommonModuleInit, ModuleCommon, ModuleConsensusVersion};
use fedimint_core::{plugin_types_trait_impl_common, secp256k1};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use thiserror::Error;

// Common contains types shared by both the client and server

// The client (and, in later phases, server) configuration
pub mod config;
pub mod endpoint_constants;
pub mod user_op;

/// Unique name for this module
pub const KIND: ModuleKind = ModuleKind::from_static_str("usdt");

/// Modules are non-compatible with older versions
pub const MODULE_CONSENSUS_VERSION: ModuleConsensusVersion = ModuleConsensusVersion::new(0, 0);

/// The [`AmountUnit`] that USDT-denominated ecash is issued in.
///
/// This is a coordination constant: it must be used both as the
/// `mintv2` config-gen param (`fedimint_mintv2_common::config::MintGenParams
/// { amount_unit: USDT_UNIT, .. }`) for the mint instance that issues
/// USDT-denominated notes, *and* by the usdt module's own consensus logic
/// (`process_input`/`process_output`, added in a later phase) when crediting
/// or debiting a guardian-observed USDT deposit/withdrawal. The client's
/// per-unit primary-module routing (`Client::primary_module_for_unit`) keys
/// off this exact value, so any mismatch between the mint instance's
/// configured unit and the value the usdt module credits would silently
/// route balance to the wrong (or no) mint instance.
pub const USDT_UNIT: AmountUnit = AmountUnit::new_custom(1);

/// A 20-byte EVM (Ethereum-style) address.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct EvmAddress(pub [u8; 20]);

impl fmt::Display for EvmAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x")?;

        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }

        Ok(())
    }
}

impl std::str::FromStr for EvmAddress {
    type Err = anyhow::Error;

    /// Parses the inverse of [`Self::fmt`]: an optionally `0x`-prefixed,
    /// 40-hex-character (20-byte) address.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex_str = s.strip_prefix("0x").unwrap_or(s);
        anyhow::ensure!(
            hex_str.len() == 40,
            "EvmAddress must be a (optionally 0x-prefixed) 20-byte hex address, got {} hex chars in {s:?}",
            hex_str.len()
        );

        let mut bytes = [0u8; 20];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16)
                .with_context(|| format!("invalid hex byte at position {i} in {s:?}"))?;
        }

        Ok(Self(bytes))
    }
}

/// An amount of USDT expressed in its smallest on-chain unit (10^-6 USDT).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct UsdtAmount(pub u64);

impl fmt::Display for UsdtAmount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A federation member's vote on the current EVM fee market and USDT/ETH
/// exchange rate.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct FeeVote {
    pub max_fee_per_gas_wei: u64,
    pub usdt_per_eth_e6: u64,
}

impl fmt::Display for FeeVote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "FeeVote(max_fee_per_gas_wei={}, usdt_per_eth_e6={})",
            self.max_fee_per_gas_wei, self.usdt_per_eth_e6
        )
    }
}

/// Domain-separation tag mixed into a deposit account's CREATE2 `salt` (see
/// [`derive_deposit_account`]).
pub const DEPOSIT_ADDRESS_DOMAIN: &[u8] = b"fedimint-usdt-deposit-v0";

/// Domain-separation tag mixed into a signing session's id derivation (see
/// [`signing_session_id`]).
pub const SIGNING_SESSION_DOMAIN: &[u8] = b"fedimint-usdt-signing-v0";

/// The standard Ethereum address of a secp256k1 public key: last 20 bytes of
/// `keccak256` over the 64-byte uncompressed point (SEC1 with the `0x04`
/// prefix stripped). WASM-safe (pure-Rust `sha3`); mirrors
/// `fedimint_threshold_ecdsa::evm_address`, and is independently verified
/// against the same canonical test vector as
/// `fedimint_threshold_ecdsa::evm_address`.
#[must_use]
pub fn evm_address(pk: &secp256k1::PublicKey) -> EvmAddress {
    let uncompressed = pk.serialize_uncompressed();
    let hash = Keccak256::digest(&uncompressed[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    EvmAddress(address)
}

alloy_sol_types::sol! {
    /// Only the ABI signature is needed here (to produce `initialize`'s
    /// calldata for [`derive_deposit_account`]'s `initCode`); mirrors
    /// `SimpleAccount.initialize(address)` from the vendored
    /// `fedimint-usdt-tests/tests/fixtures/erc4337/SimpleAccount.json`
    /// (Phase 7 Task 1, `@account-abstraction/contracts@0.7.0`).
    interface ISimpleAccountInit {
        function initialize(address anOwner) external;
    }
}

/// The `ERC1967Proxy` creation (constructor) bytecode that
/// `SimpleAccountFactory.createAccount`/`getAddress` embed in the `initCode`
/// they `CREATE2` a counterfactual `SimpleAccount` proxy from (`new
/// ERC1967Proxy{salt: bytes32(salt)}(address(accountImplementation),
/// abi.encodeCall(SimpleAccount.initialize, (owner)))`).
///
/// Source: `eth-infinitism/account-abstraction` git tag `v0.7.0`'s own
/// `hardhat compile` output for
/// `artifacts/@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol/
/// ERC1967Proxy.json`'s `bytecode` field, committed here as this hex
/// literal.
///
/// NOTE: this is deliberately **not** `@openzeppelin/contracts@5.0.0`'s own
/// standalone-published artifact (`build/contracts/ERC1967Proxy.json` on
/// unpkg), even though that resolves to the identical Solidity source (the
/// exact version `@account-abstraction/contracts@0.7.0` pins via its
/// `yarn.lock` at this tag) compiled with the same solc `0.8.23` and
/// `optimizer.runs = 1000000` (`hardhat.config.ts`). The two artifacts'
/// bytecode differs anyway: `hardhat compile` (no explicit `evmVersion`
/// override) resolves solc 0.8.23's default target to `paris`, whereas a
/// bare `forge build` of the same source/solc/optimizer settings defaults
/// to `shanghai` (PUSH0-era codegen) -- a real, confirmed divergence, not a
/// hypothetical one (`derive_deposit_account_matches_factory_get_address`
/// below caught it during development). This constant was extracted by
/// actually cloning the tag, `npm install`-ing its declared dependencies
/// (resolving `@openzeppelin/contracts` to `5.0.0`, matching `yarn.lock`),
/// and running `npx hardhat compile`; the resulting `SimpleAccountFactory`
/// artifact byte-for-byte matches the one vendored in
/// `fedimint-usdt-tests/tests/fixtures/erc4337/SimpleAccountFactory.json`
/// (Phase 7 Task 1, fetched from unpkg), confirming this is the exact
/// toolchain/settings that produced it, and this exact `ERC1967Proxy`
/// bytecode is a literal contiguous substring of that artifact's
/// `deployedBytecode` (the `new ERC1967Proxy{salt}(...)` call embeds it
/// verbatim).
///
/// Pinned against the real on-chain factory (not just trusted as copied
/// correctly) by this module's self-verifying anvil test,
/// `fedimint-usdt-tests/tests/erc4337_harness.rs`'s
/// `derive_deposit_account_matches_factory_get_address`: if this constant
/// were wrong, off-chain [`derive_deposit_account`] would disagree with
/// `SimpleAccountFactory.getAddress` there.
const ERC1967_PROXY_CREATION_CODE: &[u8] = &alloy_primitives::hex!(
    "6080604052604051610417380380610417833981016040819052610022916102"
    "68565b61002c8282610033565b5050610352565b61003c82610092565b604051"
    "6001600160a01b038316907fbc7cd75a20ee27fd9adebab32041f755214dbc6b"
    "ffa90cc0225b39da2e5c2d3b90600090a280511561008657610081828261010e"
    "565b505050565b61008e610185565b5050565b806001600160a01b03163b6000"
    "036100cd57604051634c9c8ce360e01b81526001600160a01b03821660048201"
    "526024015b60405180910390fd5b7f360894a13ba1a3210667c828492db98dca"
    "3e2076cc3735a920a3ca505d382bbc80546001600160a01b0319166001600160"
    "a01b0392909216919091179055565b6060600080846001600160a01b03168460"
    "405161012b9190610336565b600060405180830381855af49150503d80600081"
    "14610166576040519150601f19603f3d011682016040523d82523d6000602084"
    "013e61016b565b606091505b50909250905061017c8583836101a6565b959450"
    "50505050565b34156101a45760405163b398979f60e01b815260040160405180"
    "910390fd5b565b6060826101bb576101b682610205565b6101fe565b81511580"
    "156101d257506001600160a01b0384163b155b156101fb57604051639996b315"
    "60e01b81526001600160a01b03851660048201526024016100c4565b50805b93"
    "92505050565b8051156102155780518082602001fd5b604051630a12f52160e1"
    "1b815260040160405180910390fd5b634e487b7160e01b600052604160045260"
    "246000fd5b60005b8381101561025f578181015183820152602001610247565b"
    "50506000910152565b6000806040838503121561027b57600080fd5b82516001"
    "600160a01b038116811461029257600080fd5b60208401519092506001600160"
    "401b03808211156102af57600080fd5b818501915085601f8301126102c35760"
    "0080fd5b8151818111156102d5576102d561022e565b604051601f8201601f19"
    "908116603f011681019083821181831017156102fd576102fd61022e565b8160"
    "405282815288602084870101111561031657600080fd5b610327836020830160"
    "208801610244565b80955050505050509250929050565b600082516103488184"
    "60208701610244565b9190910192915050565b60b7806103606000396000f3fe"
    "6080604052600a600c565b005b60186014601a565b605e565b565b600060597f"
    "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
    "5473ffffffffffffffffffffffffffffffffffffffff1690565b905090565b36"
    "60008037600080366000845af43d6000803e808015607c573d6000f35b3d6000"
    "fdfea2646970667358221220d7f23a80daebb5531c9e4a18d87e812fca112e5d"
    "f7e56433218edcc12bbe415d64736f6c63430008170033"
);

/// The CREATE2 `salt` for `claim_pk`'s deposit account:
/// `keccak256(DEPOSIT_ADDRESS_DOMAIN ‖ claim_pk.serialize())` (compressed,
/// 33-byte). Extracted out of [`derive_deposit_account`] so
/// `fedimint-usdt-server`'s Phase-7 Task 4 `UserOp` builder can compute the
/// exact same salt for `SimpleAccountFactory.createAccount`'s `initCode`
/// without duplicating (and risking drifting from) this formula.
#[must_use]
pub fn deposit_salt(claim_pk: &secp256k1::PublicKey) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(DEPOSIT_ADDRESS_DOMAIN);
    hasher.update(claim_pk.serialize()); // 33-byte compressed
    hasher.finalize().into()
}

/// Derives the counterfactual CREATE2 address of the per-`claim_pk`
/// ERC-4337 v0.7 `SimpleAccount` deposit account (D3, Phase 7 Task 2's
/// reconciliation of Phase 5's provisional additive-tweak EOA):
///
/// - `owner = evm_address(group_public_key)` -- a single DKG group key owns
///   *every* deposit account (differentiated only by `salt`), so one MPC key
///   signs every sweep, and (since it's an ERC-4337 smart account) the token
///   paymaster pays gas in USDT, so a deposit address never needs ETH.
/// - `salt = keccak256(DEPOSIT_ADDRESS_DOMAIN ‖ claim_pk.serialize())`
///   (compressed, 33-byte).
/// - `initCode = ERC1967Proxy_creationCode ‖ abi.encode(simple_account_impl,
///   SimpleAccount.initialize(owner))`, mirroring
///   `SimpleAccountFactory.createAccount`'s `new ERC1967Proxy{salt}(
///   address(accountImplementation), abi.encodeCall(SimpleAccount.initialize,
///   (owner)))`.
/// - `address = keccak256(0xff ‖ account_factory ‖ salt ‖
///   keccak256(initCode))[12..]` (EIP-1014), via
///   [`alloy_primitives::Address::create2_from_code`].
///
/// Pure function, no RPC -- both the client (wasm) and every guardian call
/// this exact function so the address they watch is bit-for-bit identical.
/// Self-verified against `SimpleAccountFactory.getAddress` on a real
/// anvil-deployed factory by
/// `fedimint-usdt-tests/tests/erc4337_harness.rs`.
#[must_use]
pub fn derive_deposit_account(
    group_public_key: &secp256k1::PublicKey,
    account_factory: EvmAddress,
    simple_account_impl: EvmAddress,
    claim_pk: &secp256k1::PublicKey,
) -> EvmAddress {
    use alloy_sol_types::{SolCall as _, SolValue as _};

    let owner = evm_address(group_public_key);
    let salt = deposit_salt(claim_pk);

    let initialize_calldata = ISimpleAccountInit::initializeCall {
        anOwner: alloy_primitives::Address::from(owner.0),
    }
    .abi_encode();
    // `abi.encode(address, bytes)`, matching `ERC1967Proxy`'s
    // `constructor(address implementation, bytes memory _data)`.
    let ctor_args = (
        alloy_primitives::Address::from(simple_account_impl.0),
        alloy_primitives::Bytes::from(initialize_calldata),
    )
        .abi_encode_params();

    let mut init_code = ERC1967_PROXY_CREATION_CODE.to_vec();
    init_code.extend_from_slice(&ctor_args);

    let factory_address = alloy_primitives::Address::from(account_factory.0);
    let derived = factory_address.create2_from_code(salt, init_code);

    EvmAddress(derived.into_array())
}

/// Identifies one instance of the guardians co-signing a single 32-byte
/// digest (see [`signing_session_id`]). Plain data — wasm-safe, carries no
/// cggmp21 state.
#[derive(
    Debug,
    Clone,
    Copy,
    Eq,
    PartialEq,
    Hash,
    Ord,
    PartialOrd,
    Serialize,
    Deserialize,
    Encodable,
    Decodable,
)]
pub struct SigningSessionId(pub [u8; 32]);

/// Derives the id of the signing session for `digest` on its `attempt`'th
/// retry: `keccak256(SIGNING_SESSION_DOMAIN ‖ digest ‖ attempt.to_be_bytes())`.
///
/// Mirrors [`derive_deposit_account`]'s keccak-construction style. Including
/// `attempt` lets the federation restart signing for the same digest (e.g.
/// after a failed round) under a fresh session id, without colliding with the
/// abandoned attempt's DB records.
#[must_use]
pub fn signing_session_id(digest: &[u8; 32], attempt: u32) -> SigningSessionId {
    let mut hasher = Keccak256::new();
    hasher.update(SIGNING_SESSION_DOMAIN);
    hasher.update(digest);
    hasher.update(attempt.to_be_bytes());
    SigningSessionId(hasher.finalize().into())
}

/// Maximum size, in bytes, of a single [`MpcRoundItem`] chunk's `payload`.
///
/// A cggmp21 signing round's full per-peer message can be tens of kilobytes
/// (round 2 is ≈63 KB), but Fedimint's `AlephBFT` unit byte limit
/// (`ALEPH_BFT_UNIT_BYTE_LIMIT = 50_000`) silently refuses to pack any
/// consensus item that does not fit under it into an ordered unit — so a
/// single oversized `MpcRound` item would never be ordered and the signing
/// session would stall forever. Each round's payload is therefore split into
/// chunks of at most this many bytes, each carried as its own `MpcRound`
/// consensus item and reassembled deterministically before being fed to the
/// signer. 30 KB leaves ample room under the 50 KB limit for the consensus
/// item envelope and encoding overhead.
pub const MPC_ROUND_CHUNK_SIZE: usize = 30_000;

/// One chunk of one guardian's message for a single round of a signing
/// session's cggmp21 state machine. A round's full per-peer payload can
/// exceed Fedimint's `AlephBFT` unit byte limit, so it is split into
/// [`MPC_ROUND_CHUNK_SIZE`]-byte chunks, each carried as its own `MpcRound`
/// consensus item and reassembled (by concatenating chunks `0..chunk_count`
/// in ascending index) before being interpreted. `payload` is THIS chunk's
/// opaque bytes; this module's consensus logic is the only thing that
/// interprets the reassembled whole.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct MpcRoundItem {
    pub session_id: SigningSessionId,
    pub round: u16,
    /// This chunk's index in `0..chunk_count`.
    pub chunk: u16,
    /// Total number of chunks for this `(round, peer)`'s full payload (always
    /// `>= 1`; a zero-length payload is a single empty chunk).
    pub chunk_count: u16,
    /// THIS chunk's bytes (not the whole round payload).
    pub payload: Vec<u8>,
}

/// Payload of a `UsdtConsensusItem::Deposit` observation.
///
/// `claim_pk` is carried in the observation itself (rather than being
/// recovered from a guardian's local `PendingCheck` when the item is
/// processed) so that crediting a deposit is a pure function of consensus
/// data: `process_consensus_item` must be byte-identical across every
/// honest guardian, but `PendingCheck` is guardian-local state that not
/// every guardian is guaranteed to have (e.g. a `check_deposit` API call
/// only reaches a threshold of guardians, not all of them). See
/// `Usdt::credit_deposit`'s doc comment in `fedimint-usdt-server` for the
/// full argument.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct DepositObservation {
    pub account: EvmAddress,
    pub balance: UsdtAmount,
    pub block: u64,
    pub claim_pk: secp256k1::PublicKey,
}

/// Request to enqueue this guardian's local deposit-checker task to start
/// watching `claim_pk`'s deposit address (see [`derive_deposit_account`]),
/// and to have the derived address returned to the caller. Idempotent: a
/// repeated request for the same `claim_pk` does not overwrite an
/// already-enqueued [check][CheckDepositResponse].
#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct CheckDepositRequest {
    pub claim_pk: secp256k1::PublicKey,
}

/// Response to [`CheckDepositRequest`]: the derived deposit account.
///
/// Deliberately does not report whether this call is what enqueued the
/// guardian-local check: that is guardian-local state (some guardians may
/// already have a `PendingCheck` enqueued for this account, others
/// may not), so including it here would let honest guardians return
/// different responses to the same request, breaking the threshold-identical
/// response requirement of `request_current_consensus`.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct CheckDepositResponse {
    pub account: EvmAddress,
}

/// Request for the current credited/claimed/claimable state of `claim_pk`'s
/// deposit account.
#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct DepositStatusRequest {
    pub claim_pk: secp256k1::PublicKey,
}

/// Response to [`DepositStatusRequest`]. `claimable` is `credited − claimed`
/// (saturating). If no deposit has been credited yet (or observed at all),
/// `credited`/`claimed`/`claimable` are all zero, with `account` still set to
/// the derived deposit address so the client can poll this endpoint before
/// any credit lands.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct DepositStatusResponse {
    pub account: EvmAddress,
    pub credited: UsdtAmount,
    pub claimed: UsdtAmount,
    pub claimable: UsdtAmount,
}

/// Per-instance config-gen params for the USDT module (Phase 4.5 mechanism).
///
/// `Default` targets a local `anvil` dev federation: chain id 31337 and a
/// fast confirmation depth. `usdt_contract`, `entry_point`,
/// `account_factory`, and `simple_account_impl` are placeholders — real
/// deployments (and the devimint e2e) must override these with the deployed
/// contract addresses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsdtGenParams {
    pub usdt_contract: EvmAddress,
    pub chain_id: u64,
    pub confirmation_depth: u64,
    /// The deployed ERC-4337 v0.7 `EntryPoint` contract address (Phase 7).
    /// Placeholder; real deployments/tests must override.
    pub entry_point: EvmAddress,
    /// The deployed `SimpleAccountFactory` contract address (Phase 7).
    /// Placeholder; real deployments/tests must override.
    pub account_factory: EvmAddress,
    /// The deployed `SimpleAccount` implementation contract address (Phase
    /// 7). Placeholder; real deployments/tests must override.
    pub simple_account_impl: EvmAddress,
    pub check_ttl_blocks: u64,
}

impl Default for UsdtGenParams {
    fn default() -> Self {
        Self {
            usdt_contract: EvmAddress([0u8; 20]),
            chain_id: 31337,
            confirmation_depth: 1,
            entry_point: EvmAddress([0u8; 20]),
            account_factory: EvmAddress([0u8; 20]),
            simple_account_impl: EvmAddress([0u8; 20]),
            check_ttl_blocks: 10_000,
        }
    }
}

/// Non-transaction items that will be submitted to consensus
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum UsdtConsensusItem {
    /// Guardian's view of the EVM chain head (median-voted, wallet-style).
    BlockCount(u64),
    /// Guardian's observation of a pending deposit account's confirmed
    /// balance (claim-triggered, D7).
    Deposit(DepositObservation),
    /// One guardian's message for a single round of a signing session's
    /// cggmp21 state machine (Phase 6a).
    MpcRound(MpcRoundItem),
    /// Starts a threshold-ECDSA signing session over `digest` on every
    /// guardian, atomically, in consensus order (Phase 6a). Deliberately a
    /// consensus item rather than a per-guardian API call: if guardians
    /// started sessions independently, a signer could propose round 0 of its
    /// `MpcRound` before another guardian had started the session, and that
    /// guardian's `process_consensus_item` would reject it as belonging to
    /// an unknown session, stalling the round. Processing this item is a
    /// pure function of the digest, prior consensus DB state, and config
    /// (see `Usdt::start_session`), so every guardian — signer or not —
    /// performs the identical `SigningSession` write.
    StartSigning { digest: [u8; 32] },
    /// A signer's federation-agreed signature for a signing session (Phase
    /// 6b). Proposed by a signer once its off-thread cggmp21 state machine
    /// finishes (see `Usdt::advance_local_signer`'s
    /// `pending_signature_proposals` queue in `fedimint-usdt-server`); every
    /// guardian — signer or not — verifies `signature` against the DKG group
    /// key and the session's digest before writing
    /// `SessionState::Completed(signature)` to the consensus `SigningSession`
    /// (see `Usdt::process_mpc_signature`). This is what makes the finished
    /// signature a federation-wide agreed record instead of guardian-local,
    /// signer-only state. `signature` is the compact 64-byte secp256k1
    /// signature.
    MpcSignature {
        session_id: SigningSessionId,
        signature: Vec<u8>,
    },
    /// Fails a stalled signing session and retries the same digest under a
    /// rotated signer subset (Phase 6b, Task 3). `session_id` is the
    /// TIMED-OUT attempt's id. Proposed by `consensus_proposal` for any
    /// `InProgress` session whose `last_progress_block` has fallen more than
    /// the timeout behind the consensus block count (a deterministic,
    /// consensus-DB-only judgement — never wall-clock — so every guardian
    /// agrees). Processing it is a pure function of the item, prior consensus
    /// DB state, and config: every guardian — signer or not — marks the
    /// timed-out `SigningSession` `Failed` and starts the next attempt
    /// (`attempt + 1`) under a rotated subset (see `Usdt::signer_subset` /
    /// `Usdt::start_session`), performing the identical consensus-DB writes.
    RotateSigning { session_id: SigningSessionId },
    #[encodable_default]
    Default { variant: u64, bytes: Vec<u8> },
}

/// Input for a fedimint transaction
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum UsdtInput {
    /// Claim credited deposit funds. Core verifies the fedimint transaction is
    /// signed by `InputMeta.pub_key` = the deposit's claim key; there is no
    /// extra signature inside the input.
    V0(UsdtInputV0),
    #[encodable_default]
    Default { variant: u64, bytes: Vec<u8> },
}

/// Data for a `UsdtInput::V0`
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct UsdtInputV0 {
    pub account: EvmAddress,
    pub amount: UsdtAmount,
}

/// Output for a fedimint transaction
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct UsdtOutput;

/// Information needed by a client to update output funds
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct UsdtOutputOutcome;

/// Errors that might be returned by the server
#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum UsdtInputError {
    #[error("No credited deposit record exists for this account")]
    UnknownDepositAccount,
    #[error("Claim of {requested} exceeds the {available} still claimable for this account")]
    InsufficientCredit {
        available: UsdtAmount,
        requested: UsdtAmount,
    },
}

/// Errors that might be returned by the server
#[derive(Debug, Clone, Eq, PartialEq, Hash, Error, Encodable, Decodable)]
pub enum UsdtOutputError {
    #[error("This module does not support outputs")]
    NotSupported,
}

/// Contains the types defined above
pub struct UsdtModuleTypes;

// Wire together the types for this module
plugin_types_trait_impl_common!(
    KIND,
    UsdtModuleTypes,
    UsdtClientConfig,
    UsdtInput,
    UsdtOutput,
    UsdtOutputOutcome,
    UsdtConsensusItem,
    UsdtInputError,
    UsdtOutputError
);

#[derive(Debug)]
pub struct UsdtCommonInit;

impl CommonModuleInit for UsdtCommonInit {
    const CONSENSUS_VERSION: ModuleConsensusVersion = MODULE_CONSENSUS_VERSION;
    const KIND: ModuleKind = KIND;

    type ClientConfig = UsdtClientConfig;

    fn decoder() -> Decoder {
        UsdtModuleTypes::decoder_builder().build()
    }
}

impl fmt::Display for UsdtInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl fmt::Display for UsdtOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UsdtOutput")
    }
}

impl fmt::Display for UsdtOutputOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UsdtOutputOutcome")
    }
}

impl fmt::Display for UsdtConsensusItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

#[cfg(test)]
mod tests {
    use fedimint_core::core::ModuleKind;
    use fedimint_core::encoding::{Decodable, Encodable};
    use fedimint_core::module::registry::ModuleDecoderRegistry;

    use super::*;

    #[test]
    fn test_kind_is_usdt() {
        assert_eq!(KIND, ModuleKind::from_static_str("usdt"));
    }

    #[test]
    fn test_evm_address_round_trips_through_consensus_encoding() {
        let address = EvmAddress([0x11; 20]);
        let bytes = address.consensus_encode_to_vec();
        let decoded = EvmAddress::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
            .expect("EvmAddress should decode what it just encoded");

        assert_eq!(address, decoded);
    }

    #[test]
    fn test_usdt_amount_round_trips_through_consensus_encoding() {
        let amount = UsdtAmount(1_000_000);
        let bytes = amount.consensus_encode_to_vec();
        let decoded = UsdtAmount::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
            .expect("UsdtAmount should decode what it just encoded");

        assert_eq!(amount, decoded);
    }

    #[test]
    fn test_fee_vote_round_trips_through_consensus_encoding() {
        let vote = FeeVote {
            max_fee_per_gas_wei: 30_000_000_000,
            usdt_per_eth_e6: 3_000_000_000,
        };
        let bytes = vote.consensus_encode_to_vec();
        let decoded = FeeVote::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
            .expect("FeeVote should decode what it just encoded");

        assert_eq!(vote, decoded);
    }

    #[test]
    fn test_evm_address_display_is_lowercase_hex_with_0x_prefix() {
        let address = EvmAddress([
            0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45,
            0x67, 0x89, 0xab, 0xcd, 0xef, 0x01,
        ]);
        let rendered = address.to_string();

        assert!(rendered.starts_with("0x"));
        assert_eq!(rendered.len(), 42);
        assert!(
            rendered
                .chars()
                .skip(2)
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn test_module_decoder_builds() {
        let _decoder = UsdtModuleTypes::decoder_builder().build();
    }

    fn hex_20(s: &str) -> [u8; 20] {
        let bytes = (0..20)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect::<Vec<_>>();
        bytes.try_into().unwrap()
    }

    #[test]
    fn evm_address_matches_keccak_last_20_of_uncompressed() {
        // A fixed secp256k1 pubkey → its well-known Ethereum address.
        // Secret key = 0x0000...0001; address is the canonical test vector.
        let sk = secp256k1::SecretKey::from_slice(&{
            let mut b = [0u8; 32];
            b[31] = 1;
            b
        })
        .expect("valid scalar");
        let pk = sk.public_key(secp256k1::SECP256K1);
        // keccak256(uncompressed[1..])[12..] for sk=1:
        let expected = EvmAddress(hex_20("7e5f4552091a69125d5dfcb7b8c2659029395bdf"));
        assert_eq!(evm_address(&pk), expected);
    }

    #[test]
    fn derive_deposit_account_is_deterministic_and_claim_specific() {
        let group = secp256k1::SecretKey::from_slice(&[2u8; 32])
            .unwrap()
            .public_key(secp256k1::SECP256K1);
        let claim_a = secp256k1::SecretKey::from_slice(&[3u8; 32])
            .unwrap()
            .public_key(secp256k1::SECP256K1);
        let claim_b = secp256k1::SecretKey::from_slice(&[4u8; 32])
            .unwrap()
            .public_key(secp256k1::SECP256K1);
        // Fixed non-zero test constants; the CREATE2 math is exercised
        // end-to-end (and pinned against a real on-chain factory) by
        // `fedimint-usdt-tests/tests/erc4337_harness.rs`, so any non-zero
        // addresses suffice here.
        let factory = EvmAddress([0xfa; 20]);
        let simple_account_impl = EvmAddress([0x1e; 20]);

        // Deterministic
        assert_eq!(
            derive_deposit_account(&group, factory, simple_account_impl, &claim_a),
            derive_deposit_account(&group, factory, simple_account_impl, &claim_a)
        );
        // Distinct per claim key
        assert_ne!(
            derive_deposit_account(&group, factory, simple_account_impl, &claim_a),
            derive_deposit_account(&group, factory, simple_account_impl, &claim_b)
        );
        // Distinct from the bare (untweaked) group-key EOA address: the
        // deposit account is a CREATE2 *smart contract* address, never
        // literally `evm_address(group_public_key)`.
        assert_ne!(
            derive_deposit_account(&group, factory, simple_account_impl, &claim_a),
            evm_address(&group)
        );
        // Distinct per factory (a different `SimpleAccountFactory` deployment
        // must never collide with another's counterfactual addresses).
        let other_factory = EvmAddress([0xfb; 20]);
        assert_ne!(
            derive_deposit_account(&group, factory, simple_account_impl, &claim_a),
            derive_deposit_account(&group, other_factory, simple_account_impl, &claim_a)
        );
        // Distinct per `simple_account_impl` (changes `initCode`, hence the
        // CREATE2 address).
        let other_impl = EvmAddress([0x1f; 20]);
        assert_ne!(
            derive_deposit_account(&group, factory, simple_account_impl, &claim_a),
            derive_deposit_account(&group, factory, other_impl, &claim_a)
        );
    }

    #[test]
    fn test_usdt_consensus_item_block_count_round_trips_through_consensus_encoding() {
        let item = UsdtConsensusItem::BlockCount(7);
        let bytes = item.consensus_encode_to_vec();
        let decoded =
            UsdtConsensusItem::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
                .expect("UsdtConsensusItem::BlockCount should decode what it just encoded");

        assert_eq!(item, decoded);
    }

    #[test]
    fn test_usdt_consensus_item_deposit_round_trips_through_consensus_encoding() {
        let claim_pk = secp256k1::SecretKey::from_slice(&[5u8; 32])
            .unwrap()
            .public_key(secp256k1::SECP256K1);
        let item = UsdtConsensusItem::Deposit(DepositObservation {
            account: EvmAddress([9; 20]),
            balance: UsdtAmount(1_000_000),
            block: 42,
            claim_pk,
        });
        let bytes = item.consensus_encode_to_vec();
        let decoded =
            UsdtConsensusItem::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
                .expect("UsdtConsensusItem::Deposit should decode what it just encoded");

        assert_eq!(item, decoded);
    }

    #[test]
    fn test_usdt_consensus_item_mpc_round_round_trips_through_consensus_encoding() {
        let item = UsdtConsensusItem::MpcRound(MpcRoundItem {
            session_id: SigningSessionId([7; 32]),
            round: 3,
            chunk: 1,
            chunk_count: 2,
            payload: vec![1, 2, 3],
        });
        let bytes = item.consensus_encode_to_vec();
        let decoded =
            UsdtConsensusItem::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
                .expect("UsdtConsensusItem::MpcRound should decode what it just encoded");

        assert_eq!(item, decoded);
    }

    #[test]
    fn test_usdt_consensus_item_mpc_signature_round_trips_through_consensus_encoding() {
        let item = UsdtConsensusItem::MpcSignature {
            session_id: SigningSessionId([8; 32]),
            signature: vec![1; 64],
        };
        let bytes = item.consensus_encode_to_vec();
        let decoded =
            UsdtConsensusItem::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
                .expect("UsdtConsensusItem::MpcSignature should decode what it just encoded");

        assert_eq!(item, decoded);
    }

    #[test]
    fn test_usdt_consensus_item_rotate_signing_round_trips_through_consensus_encoding() {
        let item = UsdtConsensusItem::RotateSigning {
            session_id: SigningSessionId([5; 32]),
        };
        let bytes = item.consensus_encode_to_vec();
        let decoded =
            UsdtConsensusItem::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
                .expect("UsdtConsensusItem::RotateSigning should decode what it just encoded");

        assert_eq!(item, decoded);
    }

    #[test]
    fn signing_session_id_is_deterministic_and_attempt_sensitive() {
        let digest = [9u8; 32];

        assert_eq!(
            signing_session_id(&digest, 0),
            signing_session_id(&digest, 0)
        );
        assert_ne!(
            signing_session_id(&digest, 0),
            signing_session_id(&digest, 1)
        );
    }

    #[test]
    fn test_usdt_input_v0_round_trips_through_consensus_encoding() {
        let input = UsdtInput::V0(UsdtInputV0 {
            account: EvmAddress([9; 20]),
            amount: UsdtAmount(1_000_000),
        });
        let bytes = input.consensus_encode_to_vec();
        let decoded = UsdtInput::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
            .expect("UsdtInput::V0 should decode what it just encoded");

        assert_eq!(input, decoded);
    }
}
