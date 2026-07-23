#![deny(clippy::pedantic)]
#![allow(clippy::module_name_repetitions)]

use std::fmt;

use anyhow::Context as _;
use config::UsdtClientConfig;
use fedimint_core::core::{Decoder, ModuleInstanceId, ModuleKind};
use fedimint_core::encoding::{Decodable, Encodable};
use fedimint_core::module::{AmountUnit, CommonModuleInit, ModuleCommon, ModuleConsensusVersion};
use fedimint_core::{OutPoint, plugin_types_trait_impl_common, secp256k1};
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

/// Total gas-unit estimate for a single-transfer withdrawal `UserOp` (pool
/// already deployed): the sum of the three ERC-4337 gas components the
/// builder provisions for a batch of one: `verification_gas_limit`
/// (`100_000`), `call_gas_limit` (`140_000`), and `pre_verification_gas`
/// (`120_000`).
///
/// A withdrawal is quoted per-item BEFORE its batch is composed, so the only
/// safe (never-undercharging) figure is this batch-of-1 total; larger
/// batches amortize the fixed per-batch overhead and over-collect slightly
/// (safe). Kept in lockstep with `GasBounds::withdrawal_batch(1, false)` by
/// `withdrawal_gas_units_matches_the_batch_of_one_builder_bound`.
pub const WITHDRAWAL_GAS_UNITS: u128 = 360_000;

/// Percentage buffer [`withdrawal_fee_quote`] applies on top of the raw
/// gas-cost estimate, covering fee-market movement between the quote being
/// given out and the withdrawal batch actually landing on-chain (Task 2's
/// batching delay), as well as [`WITHDRAWAL_GAS_UNITS`]'s own imprecision.
/// `20` == 20%.
pub const WITHDRAWAL_FEE_BUFFER_PERCENT: u128 = 20;

/// Floor applied by [`withdrawal_fee_quote`] on top of the computed
/// gas-cost-derived fee (Phase 9, Task 1 hardening; deferred from Phase 8).
///
/// Without a floor, a degenerate consensus [`FeeVote`] median -- e.g. every
/// guardian voting `max_fee_per_gas_wei: 0` or `usdt_per_eth_e6: 0` (whether
/// by misconfiguration, an EVM RPC that always reports a zero base fee such
/// as an idle `anvil` devnet, or a byzantine minority trying to zero out the
/// median) -- would make [`withdrawal_fee_quote`] return `Some(UsdtAmount(0))`,
/// letting `process_output` accept a withdrawal with `max_fee: 0`: a
/// completely free withdrawal that drains the pool with no fee revenue to
/// cover the guardians' real on-chain gas cost.
///
/// `10_000` raw units == `0.01` USDT (see [`UsdtAmount`]'s `10^-6` USDT
/// unit): large enough to guarantee the quote is never literally zero, but
/// negligible next to any realistic gas-market-derived quote (tens of
/// thousands to millions of raw units at normal EVM gas prices -- see
/// `withdrawal_fee_quote_computes_expected_value`'s `38_880_000`-unit
/// example), so it never distorts a real quote and only ever bites in the
/// degenerate zero-median edge case this const exists to close.
pub const MIN_WITHDRAWAL_FEE: UsdtAmount = UsdtAmount(10_000);

/// Computes the minimum USDT fee (in [`UsdtAmount`]'s smallest on-chain
/// unit) a withdrawal output must offer as `max_fee`, given the
/// federation's current [`FeeVote`] median (see
/// `fedimint_usdt_server::Usdt::fee_vote_median`).
///
/// `= max(MIN_WITHDRAWAL_FEE, WITHDRAWAL_GAS_UNITS *
/// median.max_fee_per_gas_wei (wei) * median.usdt_per_eth_e6 / 1e18 * (100 +
/// WITHDRAWAL_FEE_BUFFER_PERCENT) / 100)`, ceiling-rounded (`(numerator +
/// denominator - 1) / denominator`) so the federation is never left
/// undercharged by integer-division truncation, and floored at
/// [`MIN_WITHDRAWAL_FEE`] so a degenerate zero (or near-zero) `FeeVote`
/// median can never yield a free (or near-free) withdrawal (see
/// [`MIN_WITHDRAWAL_FEE`]'s doc comment).
///
/// All arithmetic happens in `u128` via `checked_*` operations: two `u64`
/// fee-vote fields multiplied together (`max_fee_per_gas_wei *
/// usdt_per_eth_e6`) can already approach `u128::MAX`, and multiplying that
/// by [`WITHDRAWAL_GAS_UNITS`] and the buffer can overflow it outright for
/// an extreme (e.g. byzantine-voted) `FeeVote` -- this returns `None` rather
/// than panicking or silently wrapping in that case. A pure function of
/// `median` alone (no RPC, no wall-clock, no `our_peer_id`), so every
/// guardian computes byte-identical output from the same consensus-agreed
/// median; [`MIN_WITHDRAWAL_FEE`] is a compile-time const, so the `max` with
/// it stays just as deterministic.
#[must_use]
pub fn withdrawal_fee_quote(median: &FeeVote) -> Option<UsdtAmount> {
    const WEI_PER_ETH: u128 = 1_000_000_000_000_000_000;

    let gas_cost_wei = WITHDRAWAL_GAS_UNITS.checked_mul(u128::from(median.max_fee_per_gas_wei))?;
    let numerator = gas_cost_wei
        .checked_mul(u128::from(median.usdt_per_eth_e6))?
        .checked_mul(100 + WITHDRAWAL_FEE_BUFFER_PERCENT)?;
    let denominator = WEI_PER_ETH.checked_mul(100)?;
    let fee = numerator
        .checked_add(denominator - 1)?
        .checked_div(denominator)?
        .max(u128::from(MIN_WITHDRAWAL_FEE.0));

    u64::try_from(fee).ok().map(UsdtAmount)
}

/// Converts a Chainlink ETH/USD `latestRoundData()` reading into
/// [`FeeVote::usdt_per_eth_e6`], applying sanity + staleness guards. Pure and
/// WASM-safe (integer math only). Returns `None` — meaning the guardian should
/// ABSTAIN from voting a price this cycle — when the reading is unusable:
/// non-positive `answer`, incomplete round (`answered_in_round < round_id`),
/// stale (`chain_now - updated_at > max_staleness_secs`, or `updated_at` in the
/// future), or the `answer * 1e6 / 10^feed_decimals` conversion overflows.
/// All inputs are read from the on-chain feed by the caller (see
/// `fedimint_usdt_server::rpc::AlloyEvmRpc::get_fee_estimate`).
#[must_use]
pub fn chainlink_eth_usd_to_usdt_per_eth_e6(
    answer: i128,
    feed_decimals: u8,
    round_id: u128,
    answered_in_round: u128,
    updated_at: u64,
    chain_now: u64,
    max_staleness_secs: u64,
) -> Option<u64> {
    if answer <= 0 || answered_in_round < round_id {
        return None;
    }
    // `checked_sub` returns None if `updated_at` is in the future.
    if chain_now.checked_sub(updated_at)? > max_staleness_secs {
        return None;
    }
    let answer = u128::try_from(answer).ok()?;
    let scaled = answer.checked_mul(1_000_000)?; // 1e6 USDT fixed-point
    let divisor = 10u128.checked_pow(u32::from(feed_decimals))?;
    u64::try_from(scaled.checked_div(divisor)?).ok()
}

/// Domain-separation tag mixed into a deposit account's CREATE2 `salt` (see
/// [`derive_deposit_account`]).
pub const DEPOSIT_ADDRESS_DOMAIN: &[u8] = b"fedimint-usdt-deposit-v0";

/// Domain-separation tag whose `keccak256` IS the pool account's CREATE2
/// `salt` directly (see [`derive_pool_account`]) -- unlike
/// [`DEPOSIT_ADDRESS_DOMAIN`], which is only ever mixed with a `claim_pk`
/// (never used bare), the pool account is a single, fixed, well-known
/// address per federation, so its salt has nothing else to be
/// domain-separated against.
pub const POOL_ACCOUNT_DOMAIN: &[u8] = b"fedimint-usdt-pool-v0";

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

/// The `CREATE` (nonce-based, non-CREATE2) contract address a `deployer`
/// account produces at a given `nonce`: `keccak256(rlp([deployer,
/// nonce]))[12..]` (the classic Ethereum contract-creation address rule,
/// EIP-161 §1).
///
/// Used by Part A to predict the `SimpleAccount` implementation the
/// `SimpleAccountFactory`'s constructor deploys as its first internal `CREATE`
/// (`new SimpleAccount(entryPoint)`, i.e. `create_address(factory, 1)`); kept
/// general over `nonce` even though the module only ever needs `1`.
///
/// Pure function, WASM-safe (pure-Rust `sha3`, no `alloy-rlp`): the two-item
/// RLP list `[20-byte address, nonce]` is short enough to hand-encode. For
/// `nonce == 1` this is exactly `keccak256(0xd6 ‖ 0x94 ‖ deployer ‖
/// 0x01)[12..]`. Verified against known Ethereum `CREATE` vectors in this
/// crate's tests and pinned against a real on-chain `accountImplementation()`
/// by `fedimint-usdt-tests`' live-anvil `factory_pinning` test.
#[must_use]
pub fn create_address(deployer: EvmAddress, nonce: u64) -> EvmAddress {
    // The nonce's minimal big-endian encoding (leading zero bytes stripped);
    // empty when `nonce == 0`. A `u64` has at most 8 significant bytes.
    let be = nonce.to_be_bytes();
    let significant = match be.iter().position(|&b| b != 0) {
        Some(first) => &be[first..],
        None => &[][..],
    };

    // RLP-encode the nonce (an integer): 0 -> empty string 0x80; a single byte
    // in `0x00..=0x7f` -> the byte itself; otherwise 0x80+len followed by the
    // significant bytes. `significant.len()` is at most 8, so the `0x80 + len`
    // byte never overflows (the `unwrap_or` branch is unreachable).
    let mut nonce_rlp = Vec::with_capacity(1 + significant.len());
    match significant {
        [] => nonce_rlp.push(0x80),
        [b] if *b < 0x80 => nonce_rlp.push(*b),
        _ => {
            nonce_rlp.push(0x80 + u8::try_from(significant.len()).unwrap_or(0));
            nonce_rlp.extend_from_slice(significant);
        }
    }

    // RLP-encode the 20-byte address as a string (0x80 + 20 == 0x94, then the
    // bytes), then wrap `[address, nonce]` in a list. The payload is always
    // well under 55 bytes (21 address bytes + at most 9 nonce bytes), so the
    // list header is a single `0xc0 + len` byte (the `unwrap_or` is
    // unreachable).
    let mut payload = Vec::with_capacity(1 + 20 + nonce_rlp.len());
    payload.push(0x94);
    payload.extend_from_slice(&deployer.0);
    payload.extend_from_slice(&nonce_rlp);

    let mut rlp = Vec::with_capacity(1 + payload.len());
    rlp.push(0xc0 + u8::try_from(payload.len()).unwrap_or(0));
    rlp.extend_from_slice(&payload);

    let hash = Keccak256::digest(&rlp);
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
    let owner = evm_address(group_public_key);
    let salt = deposit_salt(claim_pk);
    create2_simple_account(account_factory, simple_account_impl, owner, salt)
}

/// The CREATE2 `salt` for the federation's fixed pool `SimpleAccount`:
/// `keccak256(POOL_ACCOUNT_DOMAIN)` (a single fixed salt, not mixed with any
/// claim key -- there is only ever one pool account per federation). Extracted
/// out of [`derive_pool_account`] (mirroring [`deposit_salt`]'s own
/// extraction out of [`derive_deposit_account`]) so
/// `fedimint-usdt-server`'s withdrawal-batch `UserOp` builder (Phase 8, Task
/// 2) can compute the exact same salt for `SimpleAccountFactory.
/// createAccount`'s `initCode` without duplicating (and risking drifting
/// from) this formula.
#[must_use]
pub fn pool_salt() -> [u8; 32] {
    Keccak256::digest(POOL_ACCOUNT_DOMAIN).into()
}

/// Derives the CREATE2 address of this federation's fixed pool `SimpleAccount`
/// -- the swept-to destination of every deploy-and-sweep `UserOp` (Phase 7
/// Task 5), and the `sender` of every withdrawal-batch `UserOp` (Phase 8,
/// Task 2): `owner = evm_address(group_public_key)` (the same group key that
/// owns every deposit account), `salt = `[`pool_salt`]`()`.
///
/// Pure function, no RPC -- every guardian (and, if a client ever needs it,
/// the client too) calls this exact function so the pool address is
/// bit-for-bit identical everywhere. Mirrors [`derive_deposit_account`]'s
/// CREATE2 construction via the shared [`create2_simple_account`] helper.
#[must_use]
pub fn derive_pool_account(
    group_public_key: &secp256k1::PublicKey,
    account_factory: EvmAddress,
    simple_account_impl: EvmAddress,
) -> EvmAddress {
    let owner = evm_address(group_public_key);
    create2_simple_account(account_factory, simple_account_impl, owner, pool_salt())
}

/// Shared CREATE2 computation behind [`derive_deposit_account`] and
/// [`derive_pool_account`]: `address = keccak256(0xff ‖ account_factory ‖
/// salt ‖ keccak256(initCode))[12..]` (EIP-1014), where `initCode =
/// ERC1967Proxy_creationCode ‖ abi.encode(simple_account_impl,
/// SimpleAccount.initialize(owner))`, mirroring
/// `SimpleAccountFactory.createAccount`'s `new ERC1967Proxy{salt}(
/// address(accountImplementation), abi.encodeCall(SimpleAccount.initialize,
/// (owner)))`. Pure function, no RPC.
fn create2_simple_account(
    account_factory: EvmAddress,
    simple_account_impl: EvmAddress,
    owner: EvmAddress,
    salt: [u8; 32],
) -> EvmAddress {
    use alloy_sol_types::{SolCall as _, SolValue as _};

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

/// Payload of a `UsdtConsensusItem::BootstrapObservation` (Part C): one
/// guardian's periodic view of whether the module's on-chain infrastructure
/// is ready to honor the full deposit->claim->sweep->withdraw lifecycle.
///
/// The first three fields are *federation facts* (the same on-chain reality
/// every honest guardian observes -- EntryPoint/factory/impl deployed and,
/// for the factory, its `getAddress` matching this build's off-chain
/// [`derive_deposit_account`] CREATE2 math); the last two are *self-facts*
/// (this guardian's own broadcaster funding and RPC health). All five are
/// counted independently and threshold-aggregated by
/// `fedimint_usdt_server::Usdt::bootstrap_state` -- no single guardian's
/// observation gates the federation's readiness (see that method's
/// determinism argument). Mirrors [`DepositObservation`]'s role in the
/// deposit-observation quorum: carried whole in the vote so the readiness
/// tally is a pure function of consensus data.
// Five independent on-chain readiness conditions, each counted separately by
// the threshold tally -- deliberately flat booleans (not a state machine), so
// `struct_excessive_bools` does not apply.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub struct BootstrapObservation {
    /// The configured `EntryPoint` has contract code deployed.
    pub entry_point_ok: bool,
    /// The configured `account_factory` has code AND its on-chain
    /// `getAddress(owner, salt)` matches this build's off-chain
    /// [`derive_pool_account`] CREATE2 derivation (the immutable-invariant
    /// check that proves derived deposit addresses are spendable -- the
    /// footgun-killer).
    pub factory_ok: bool,
    /// The configured `simple_account_impl` has contract code deployed.
    pub impl_ok: bool,
    /// This guardian's broadcaster EOA holds at least the per-chain
    /// configured minimum ETH balance to front `UserOp` gas.
    pub broadcaster_funded: bool,
    /// This guardian's last round of readiness RPC reads succeeded.
    pub rpc_healthy: bool,
}

impl fmt::Display for BootstrapObservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BootstrapObservation(entry_point_ok={}, factory_ok={}, impl_ok={}, \
             broadcaster_funded={}, rpc_healthy={})",
            self.entry_point_ok,
            self.factory_ok,
            self.impl_ok,
            self.broadcaster_funded,
            self.rpc_healthy
        )
    }
}

/// The module-level readiness state (Part C), derived by
/// `fedimint_usdt_server::Usdt::bootstrap_state` as a pure function of the
/// threshold-aggregated [`BootstrapObservation`] votes plus a persisted
/// "has ever been ready" latch.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, Encodable, Decodable)]
pub enum BootstrapState {
    /// The module is running (post-DKG) but not all readiness conditions are
    /// met yet, and it has never been `Ready`. Deposit-address handout is
    /// blocked.
    AwaitingInfra,
    /// The full deposit->claim->sweep->withdraw lifecycle is operational.
    Ready,
    /// The module was `Ready` at some point but a condition has since
    /// regressed (e.g. a broadcaster's ETH ran low). Advisory; distinguished
    /// from [`Self::AwaitingInfra`] only by the persisted latch.
    Degraded,
}

impl fmt::Display for BootstrapState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

/// Response to the `usdt_status` endpoint (Part C): the consensus-agreed
/// [`BootstrapState`] plus the per-condition tally it was derived from. Read
/// directly from consensus DB (the threshold-aggregated
/// [`BootstrapObservation`] votes + the readiness latch), so any guardian
/// answers identically (threshold-agreement via `request_current_consensus`,
/// mirroring [`PoolStateResponse`]/[`DepositStatusResponse`]).
///
/// `entry_point_ok`/`factory_ok`/`impl_ok` are the *federation facts* (each
/// `true` once at least `threshold` guardians vote it); `funded_guardians`/
/// `healthy_guardians` are the raw counts of guardians currently reporting a
/// funded broadcaster / healthy RPC (each must reach `threshold` for
/// `Ready`).
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct StatusResponse {
    pub state: BootstrapState,
    pub entry_point_ok: bool,
    pub factory_ok: bool,
    pub impl_ok: bool,
    pub funded_guardians: u16,
    pub healthy_guardians: u16,
    pub threshold: u16,
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

/// Response to the `pool_state` diagnostic endpoint (Phase 7, Task 5):
/// the pool `SimpleAccount`'s derived address (see [`derive_pool_account`])
/// and the consensus-agreed USDT balance swept into it so far. Read directly
/// from consensus DB, so any guardian answers identically once
/// `UsdtConsensusItem::UserOpConfirmed` has reached threshold agreement for
/// a sweep; `balance` is `0` (with `account` still populated) before the
/// first successful sweep, mirroring [`DepositStatusResponse`]'s
/// pre-credit-zeros shape.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct PoolStateResponse {
    pub account: EvmAddress,
    pub balance: UsdtAmount,
}

/// Request for the [`UserOpStatus`] of a specific `UserOp`, identified by its
/// [`user_op::user_op_hash`].
#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct UserOpStatusRequest {
    pub op_hash: [u8; 32],
}

/// The consensus-agreed lifecycle stage of a `UserOp` (Phase 7, Task 5):
/// `Pending` while awaiting/undergoing MPC signing (a `PendingUserOp`
/// consensus record exists), `Submitted` once federation-agreed-signed and
/// awaiting/undergoing on-chain confirmation (a `SubmittedUserOp` consensus
/// record exists), `Unknown` once confirmed (both records cleared -- see
/// [`PoolStateResponse`] for the confirmed sweep's effect) or if `op_hash`
/// was never seen at all. Read directly from consensus DB, so any guardian
/// answers identically.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub enum UserOpStatus {
    Pending,
    Submitted,
    Unknown,
}

/// Response to the `userop_status` diagnostic endpoint (Phase 7, Task 5).
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct UserOpStatusResponse {
    pub status: UserOpStatus,
}

/// Request for the current withdrawal fee quote (Phase 8, Task 1).
/// `amount` is carried for forward-compatibility with a future
/// amount-dependent fee model (e.g. a batching-size-aware quote); the
/// current [`withdrawal_fee_quote`] formula does not use it.
#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct WithdrawFeeQuoteRequest {
    pub amount: UsdtAmount,
}

/// Response to the `withdraw_fee_quote` endpoint (Phase 8, Task 1):
/// `max_fee` is the minimum fee a `UsdtOutput::V0` withdrawing `amount` must
/// offer right now; `valid_blocks` is how many further guardian-observed EVM
/// blocks the quote should be treated as valid for before re-querying
/// (fee-vote-median-derived quotes can move as guardians' `FeeVote`s
/// change), a fixed, non-consensus advisory hint rather than an enforced
/// on-chain expiry.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct WithdrawFeeQuoteResponse {
    pub max_fee: UsdtAmount,
    pub valid_blocks: u64,
}

/// Request for the current [`WithdrawalStatus`] of a withdrawal, identified
/// by the `OutPoint` of the `UsdtOutput::V0` that enqueued it (Phase 8, Task
/// 3).
#[derive(Debug, Clone, Serialize, Deserialize, Encodable, Decodable)]
pub struct WithdrawalStatusRequest {
    pub out_point: OutPoint,
}

/// Wasm-safe mirror of `fedimint_usdt_server::db::WithdrawalState` (Phase 8,
/// Task 3): the server-only type carries no cggmp21/EVM-RPC state itself
/// (it's already plain consensus-DB data), but it lives in `-server` and is
/// not reachable from a wasm client, so this is a plain-data duplicate
/// exposed over the `withdrawal_status` endpoint, mirroring how
/// [`PoolStateResponse`]/[`DepositStatusResponse`] expose other server
/// consensus-DB state to `-common`/client. Adds `Unknown` (absent from
/// `WithdrawalState` itself) for an `out_point` no `WithdrawalStateKey`
/// record exists for at all -- e.g. a typo'd or not-yet-processed
/// `OutPoint` -- mirroring [`UserOpStatus::Unknown`]'s equivalent
/// not-found sentinel.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub enum WithdrawalStatus {
    /// No `WithdrawalStateKey` record exists for the requested `OutPoint`.
    Unknown,
    /// Enqueued, awaiting the next withdrawal batch.
    Queued,
    /// Included in a withdrawal `UserOp` (`op_hash`) whose federation MPC
    /// signing session is in progress.
    Signing { op_hash: [u8; 32] },
    /// The withdrawal's `UserOp` (`op_hash`) has been federation-agreed-
    /// signed and is awaiting/undergoing guardian-local on-chain submission
    /// and confirmation.
    Submitted { op_hash: [u8; 32] },
    /// The withdrawal's `UserOp` confirmed on-chain successfully at `block`;
    /// terminal.
    Confirmed { block: u64 },
    /// The withdrawal's `UserOp` failed on-chain, or could not be
    /// completed, for `reason`; terminal.
    Failed { reason: String },
}

/// Response to the `withdrawal_status` endpoint (Phase 8, Task 3). Read
/// directly from consensus DB, so any guardian answers identically
/// (threshold-agreement via `request_current_consensus`, mirroring
/// `deposit_status`/`withdraw_fee_quote`).
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, Encodable, Decodable)]
pub struct WithdrawalStatusResponse {
    pub status: WithdrawalStatus,
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
    /// The minimum ETH balance (in wei) a guardian's broadcaster EOA must
    /// hold to count as "funded" for the Part C readiness state machine (see
    /// `BootstrapObservation::broadcaster_funded`). Genuinely per-chain (gas
    /// costs vary), so a config field rather than a compiled constant. A
    /// `u64` holds up to ~18 ETH of wei -- far above any sane per-guardian gas
    /// float, and (unlike `u128`) `fedimint_core`-`Encodable` for the
    /// consensus config it is threaded into.
    pub broadcaster_min_balance_wei: u64,
    /// Chainlink ETH/USD aggregator address whose `latestRoundData()` each
    /// guardian reads to vote `FeeVote::usdt_per_eth_e6`. Defaults to the
    /// canonical mainnet ETH/USD feed; set to `EvmAddress([0; 20])` on a chain
    /// without Chainlink (e.g. anvil) to fall back to a static price. See
    /// `chainlink_eth_usd_to_usdt_per_eth_e6`.
    pub eth_usd_price_feed: EvmAddress,
    /// Max age (seconds, chain time) of a Chainlink reading before a guardian
    /// abstains. ~1h heartbeat feeds -> 4h default is comfortably above
    /// cadence.
    pub price_feed_max_staleness_secs: u64,
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
            // 0.05 ETH: enough to front many UserOps' L1 gas on a typical
            // chain, negligible to top up on a devnet.
            broadcaster_min_balance_wei: 50_000_000_000_000_000,
            eth_usd_price_feed: EvmAddress(alloy_primitives::hex!(
                "5f4eC3Df9cbd43714FE2740f5E3616155c5b8419"
            )),
            price_feed_max_staleness_secs: 14_400,
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
    /// One guardian's threshold-voted observation that `op_hash`'s
    /// `UserOp` has landed on-chain (Phase 7, Task 5) -- mirrors
    /// [`Self::Deposit`]'s observation-quorum shape exactly (dual-prefix
    /// per-peer vote, full-field `PartialEq` tally, unbounded-history
    /// `Err`-on-redundant). `success`/`block` come from the guardian-local
    /// deposit-checker-style background task's read of
    /// `IServerEvmRpc::get_user_op_receipt` (a guardian-local RPC result,
    /// never itself a consensus write); `swept` is the amount actually
    /// moved (self-contained in the vote so the applying guardian need not
    /// re-derive it). Processing this item (`fedimint_usdt_server::Usdt::
    /// process_consensus_item`'s `UserOpConfirmed` arm) is a pure function
    /// of the item, prior consensus DB state (the per-peer vote tally and
    /// the `SubmittedUserOp`/`PoolState`/`DepositRecord` records it updates
    /// at threshold), and config -- byte-identical on every guardian,
    /// signer or not.
    UserOpConfirmed {
        op_hash: [u8; 32],
        success: bool,
        block: u64,
        swept: UsdtAmount,
    },
    /// One guardian's vote on the current EVM fee market and USDT/ETH
    /// exchange rate (Phase 8, Task 1), mirroring [`Self::BlockCount`]'s
    /// per-peer-vote shape exactly: `process_consensus_item` stores this
    /// peer's vote (with a redundancy guard) and does not itself "apply"
    /// anything at threshold -- the current fee quote is read on demand as
    /// the per-field median over all stored votes (see
    /// `fedimint_usdt_server::Usdt::fee_vote_median`), not derived from any
    /// single peer's vote. Unlike `BlockCount`'s vote (which only ever
    /// increases, so the redundancy guard is `vote > current_vote`), the EVM
    /// fee market can move in either direction, so the guard here is
    /// equality-based (reject only an EXACT repeat of this peer's current
    /// vote). `vote` comes from this guardian's local, guardian-LOCAL
    /// `IServerEvmRpc::get_fee_estimate` read (never itself a consensus
    /// decision) -- the federation-wide fee decision is always the MEDIAN
    /// read from consensus DB, never a single guardian's raw RPC value.
    FeeVote(FeeVote),
    /// One guardian's periodic observation of whether the module's on-chain
    /// infrastructure is ready to honor the full deposit->claim->sweep->
    /// withdraw lifecycle (Part C), mirroring [`Self::Deposit`]'s per-peer
    /// observation-vote shape: `process_consensus_item` stores this peer's
    /// vote under `BootstrapVoteKey(ordered-item's peer)` (with a redundancy
    /// guard) and then deterministically latches "has ever been ready" the
    /// first time the aggregate tally reaches `Ready`. The federation's
    /// readiness state is never any single guardian's raw observation -- it
    /// is the per-field threshold count over all stored votes (see
    /// `fedimint_usdt_server::Usdt::bootstrap_state`). The five booleans come
    /// from this guardian's local, guardian-LOCAL read-only EVM RPC + config
    /// (never itself a consensus decision).
    BootstrapObservation(BootstrapObservation),
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

/// Output for a fedimint transaction (Phase 8, Task 1): a user burning USDT
/// e-cash to enqueue an on-chain withdrawal.
///
/// Versioned like [`UsdtInput`] (a `V0` variant plus an
/// `#[encodable_default]` catch-all), so a future gas/fee model change can
/// add `UsdtOutput::V1` without breaking wire-compatibility with old
/// transactions still referencing `V0`.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub enum UsdtOutput {
    V0(UsdtOutputV0),
    #[encodable_default]
    Default {
        variant: u64,
        bytes: Vec<u8>,
    },
}

/// Data for a `UsdtOutput::V0`: withdraw `amount` of USDT to `recipient`,
/// offering up to `max_fee` (in the same [`UsdtAmount`] unit) to cover the
/// federation's on-chain gas cost of paying it out. The server's
/// `process_output` rejects the output (`UsdtOutputError::FeeQuoteExceeded`)
/// if `max_fee` is below the federation's current fee-vote-median-derived
/// quote (see `fedimint_usdt_common::withdrawal_fee_quote`); `amount +
/// max_fee` of `USDT_UNIT`-denominated e-cash is burned from the submitting
/// transaction's funding.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, Encodable, Decodable)]
pub struct UsdtOutputV0 {
    pub recipient: EvmAddress,
    pub amount: UsdtAmount,
    pub max_fee: UsdtAmount,
}

/// Information needed by a client to update output funds.
///
/// Deliberately minimal (a unit struct, like the pre-Phase-8 placeholder):
/// `output_status` returns `Some(UsdtOutputOutcome)` once a withdrawal has
/// been enqueued (i.e. `process_output` succeeded for this `OutPoint`) and
/// `None` otherwise, just proving the output landed. The detailed
/// [lifecycle state](crate) (`Queued`/`Signing`/`Submitted`/`Confirmed`/
/// `Failed`) is server-only (`fedimint_usdt_server::db::WithdrawalState`)
/// and tracked via a dedicated status endpoint (Task 4), not via this
/// outcome type, so it can evolve (e.g. gain the signing `UserOp` hash)
/// without a wire-breaking change here.
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
    #[error("This module does not support this output variant")]
    UnsupportedOutputVariant,
    #[error("No federation fee-vote median is available yet; withdrawals cannot be queued")]
    NoFeeQuoteAvailable,
    #[error("Computing the withdrawal fee quote overflowed")]
    FeeQuoteOverflow,
    #[error("This output's max_fee {max_fee} is below the federation's fee quote {quote}")]
    FeeQuoteExceeded {
        quote: UsdtAmount,
        max_fee: UsdtAmount,
    },
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
        write!(f, "{self:?}")
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
    fn create_address_matches_known_ethereum_vectors() {
        // Canonical EIP-161 §1 CREATE-address example: sender
        // 0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0 produces these contracts.
        let sender = "0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0"
            .parse::<EvmAddress>()
            .unwrap();
        assert_eq!(
            create_address(sender, 0),
            "0xcd234a471b72ba2f1ccf0a70fcaba648a5eecd8d"
                .parse::<EvmAddress>()
                .unwrap(),
        );
        assert_eq!(
            create_address(sender, 1),
            "0x343c43a37d37dff08ae8c4a11544c718abb4fcf8"
                .parse::<EvmAddress>()
                .unwrap(),
        );

        // Multi-byte nonce vector (nonce 0x100 == 256), exercising the
        // length-prefixed RLP integer branch.
        assert_eq!(
            create_address(sender, 256),
            "0x3837c1ae70354f670550c746580199ac6a73cb0a"
                .parse::<EvmAddress>()
                .unwrap(),
        );
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
    fn test_bootstrap_observation_round_trips_through_consensus_item_encoding() {
        let obs = BootstrapObservation {
            entry_point_ok: true,
            factory_ok: false,
            impl_ok: true,
            broadcaster_funded: false,
            rpc_healthy: true,
        };
        let item = UsdtConsensusItem::BootstrapObservation(obs);
        let bytes = item.consensus_encode_to_vec();
        let decoded =
            UsdtConsensusItem::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
                .expect("BootstrapObservation item should decode what it just encoded");

        assert_eq!(item, decoded);
    }

    #[test]
    fn test_status_response_round_trips_through_consensus_encoding() {
        let response = StatusResponse {
            state: BootstrapState::Degraded,
            entry_point_ok: true,
            factory_ok: true,
            impl_ok: true,
            funded_guardians: 2,
            healthy_guardians: 3,
            threshold: 3,
        };
        let bytes = response.consensus_encode_to_vec();
        let decoded =
            StatusResponse::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
                .expect("StatusResponse should decode what it just encoded");

        assert_eq!(response, decoded);
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
    fn test_usdt_consensus_item_user_op_confirmed_round_trips_through_consensus_encoding() {
        let item = UsdtConsensusItem::UserOpConfirmed {
            op_hash: [6; 32],
            success: true,
            block: 77,
            swept: UsdtAmount(1_234_000),
        };
        let bytes = item.consensus_encode_to_vec();
        let decoded =
            UsdtConsensusItem::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
                .expect("UsdtConsensusItem::UserOpConfirmed should decode what it just encoded");

        assert_eq!(item, decoded);
    }

    #[test]
    fn derive_pool_account_is_deterministic_and_distinct_from_deposit_accounts() {
        let group = secp256k1::SecretKey::from_slice(&[7u8; 32])
            .unwrap()
            .public_key(secp256k1::SECP256K1);
        let other_group = secp256k1::SecretKey::from_slice(&[8u8; 32])
            .unwrap()
            .public_key(secp256k1::SECP256K1);
        let claim = secp256k1::SecretKey::from_slice(&[9u8; 32])
            .unwrap()
            .public_key(secp256k1::SECP256K1);
        let factory = EvmAddress([0xfa; 20]);
        let simple_account_impl = EvmAddress([0x1e; 20]);

        // Deterministic.
        assert_eq!(
            derive_pool_account(&group, factory, simple_account_impl),
            derive_pool_account(&group, factory, simple_account_impl)
        );
        // Distinct per group key (a different federation's pool never
        // collides).
        assert_ne!(
            derive_pool_account(&group, factory, simple_account_impl),
            derive_pool_account(&other_group, factory, simple_account_impl)
        );
        // Distinct from any deposit account derived under the same group key
        // (the pool is never mistaken for a claimant's deposit address).
        assert_ne!(
            derive_pool_account(&group, factory, simple_account_impl),
            derive_deposit_account(&group, factory, simple_account_impl, &claim)
        );
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

    #[test]
    fn test_usdt_output_v0_round_trips_through_consensus_encoding() {
        let output = UsdtOutput::V0(UsdtOutputV0 {
            recipient: EvmAddress([7; 20]),
            amount: UsdtAmount(2_000_000),
            max_fee: UsdtAmount(1_000),
        });
        let bytes = output.consensus_encode_to_vec();
        let decoded = UsdtOutput::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
            .expect("UsdtOutput::V0 should decode what it just encoded");

        assert_eq!(output, decoded);
    }

    #[test]
    fn test_usdt_consensus_item_fee_vote_round_trips_through_consensus_encoding() {
        let item = UsdtConsensusItem::FeeVote(FeeVote {
            max_fee_per_gas_wei: 25_000_000_000,
            usdt_per_eth_e6: 3_200_000_000,
        });
        let bytes = item.consensus_encode_to_vec();
        let decoded =
            UsdtConsensusItem::consensus_decode_whole(&bytes, &ModuleDecoderRegistry::default())
                .expect("UsdtConsensusItem::FeeVote should decode what it just encoded");

        assert_eq!(item, decoded);
    }

    #[test]
    fn withdrawal_fee_quote_computes_expected_value() {
        // 30 gwei max_fee_per_gas, 3000.000000 USDT/ETH.
        let median = FeeVote {
            max_fee_per_gas_wei: 30_000_000_000,
            usdt_per_eth_e6: 3_000_000_000,
        };
        // gas_cost_wei = 360_000 * 30e9 = 1.08e16
        // numerator = 1.08e16 * 3_000_000_000 * 120 = 3.888e27
        // denominator = 1e18 * 100 = 1e20
        // fee = 3.888e27 / 1e20 = 38_880_000 (raw USDT units == 38.88 USDT,
        // i.e. the unbuffered 32_400_000 scaled by the 20% buffer)
        let quote = withdrawal_fee_quote(&median).expect("must not overflow for realistic input");
        assert_eq!(quote, UsdtAmount(38_880_000));
    }

    #[test]
    fn withdrawal_fee_quote_is_deterministic() {
        let median = FeeVote {
            max_fee_per_gas_wei: 87_654_321,
            usdt_per_eth_e6: 3_456_789_012,
        };
        assert_eq!(withdrawal_fee_quote(&median), withdrawal_fee_quote(&median));
    }

    #[test]
    fn withdrawal_fee_quote_scales_with_gas_price() {
        let low = FeeVote {
            max_fee_per_gas_wei: 10_000_000_000,
            usdt_per_eth_e6: 3_000_000_000,
        };
        let high = FeeVote {
            max_fee_per_gas_wei: 100_000_000_000,
            usdt_per_eth_e6: 3_000_000_000,
        };
        let quote_low = withdrawal_fee_quote(&low).expect("must not overflow");
        let quote_high = withdrawal_fee_quote(&high).expect("must not overflow");
        assert!(quote_high.0 > quote_low.0);
    }

    #[test]
    fn withdrawal_fee_quote_overflow_is_none_not_a_panic() {
        // An extreme (e.g. byzantine-voted) FeeVote whose product overflows
        // u128 part-way through the computation must return `None`, never
        // panic (no unwrap/wrapping arithmetic).
        let median = FeeVote {
            max_fee_per_gas_wei: u64::MAX,
            usdt_per_eth_e6: u64::MAX,
        };
        assert_eq!(withdrawal_fee_quote(&median), None);
    }

    #[test]
    fn chainlink_price_happy_path_8_decimals() {
        // $3000.00 at 8 decimals, fresh, complete round -> 3000_000000 (1e-6 USDT)
        let v =
            chainlink_eth_usd_to_usdt_per_eth_e6(300_000_000_000, 8, 42, 42, 1_000, 1_500, 14_400);
        assert_eq!(v, Some(3_000_000_000));
    }

    #[test]
    fn chainlink_price_rejects_non_positive_answer() {
        assert_eq!(
            chainlink_eth_usd_to_usdt_per_eth_e6(0, 8, 1, 1, 1_000, 1_000, 14_400),
            None
        );
        assert_eq!(
            chainlink_eth_usd_to_usdt_per_eth_e6(-1, 8, 1, 1, 1_000, 1_000, 14_400),
            None
        );
    }

    #[test]
    fn chainlink_price_rejects_incomplete_round() {
        // answered_in_round < round_id -> carried-over/incomplete
        assert_eq!(
            chainlink_eth_usd_to_usdt_per_eth_e6(300_000_000_000, 8, 42, 41, 1_000, 1_100, 14_400),
            None
        );
    }

    #[test]
    fn chainlink_price_rejects_stale() {
        // chain_now - updated_at (20_000) > max_staleness (14_400)
        assert_eq!(
            chainlink_eth_usd_to_usdt_per_eth_e6(300_000_000_000, 8, 1, 1, 1_000, 21_000, 14_400),
            None
        );
    }

    #[test]
    fn chainlink_price_rejects_future_timestamp() {
        // updated_at > chain_now (clock/feed anomaly) -> abstain
        assert_eq!(
            chainlink_eth_usd_to_usdt_per_eth_e6(300_000_000_000, 8, 1, 1, 2_000, 1_000, 14_400),
            None
        );
    }

    fn test_out_point(idx: u64) -> OutPoint {
        use fedimint_core::BitcoinHash as _;
        OutPoint {
            txid: fedimint_core::TransactionId::all_zeros(),
            out_idx: idx,
        }
    }

    #[test]
    fn test_withdrawal_status_request_round_trips_through_consensus_encoding() {
        let request = WithdrawalStatusRequest {
            out_point: test_out_point(3),
        };
        let bytes = request.consensus_encode_to_vec();
        let decoded = WithdrawalStatusRequest::consensus_decode_whole(
            &bytes,
            &ModuleDecoderRegistry::default(),
        )
        .expect("WithdrawalStatusRequest should decode what it just encoded");

        assert_eq!(request.out_point, decoded.out_point);
    }

    #[test]
    fn test_withdrawal_status_response_round_trips_every_variant_through_consensus_encoding() {
        let responses = [
            WithdrawalStatus::Unknown,
            WithdrawalStatus::Queued,
            WithdrawalStatus::Signing { op_hash: [1; 32] },
            WithdrawalStatus::Submitted { op_hash: [2; 32] },
            WithdrawalStatus::Confirmed { block: 99 },
            WithdrawalStatus::Failed {
                reason: "gas spike".to_string(),
            },
        ]
        .map(|status| WithdrawalStatusResponse { status });

        for response in responses {
            let bytes = response.consensus_encode_to_vec();
            let decoded = WithdrawalStatusResponse::consensus_decode_whole(
                &bytes,
                &ModuleDecoderRegistry::default(),
            )
            .expect("WithdrawalStatusResponse should decode what it just encoded");

            assert_eq!(response, decoded);
        }
    }

    #[test]
    fn test_withdrawal_status_response_round_trips_through_serde_json() {
        let response = WithdrawalStatusResponse {
            status: WithdrawalStatus::Signing { op_hash: [7; 32] },
        };
        let json = fedimint_core::module::serde_json::to_string(&response).expect("serializes");
        let decoded: WithdrawalStatusResponse = fedimint_core::module::serde_json::from_str(&json)
            .expect("WithdrawalStatusResponse should deserialize what it just serialized");

        assert_eq!(response, decoded);
    }

    #[test]
    fn withdrawal_fee_quote_zero_median_is_floored_not_free() {
        // A degenerate all-zero `FeeVote` median (e.g. an idle `anvil`
        // devnet reporting a zero base fee, or every guardian voting zeros)
        // must never yield a zero (free) withdrawal quote: the
        // `MIN_WITHDRAWAL_FEE` floor kicks in instead (Phase 9, Task 1
        // hardening).
        let median = FeeVote {
            max_fee_per_gas_wei: 0,
            usdt_per_eth_e6: 0,
        };
        let quote = withdrawal_fee_quote(&median).expect("zero median must not overflow");
        assert_eq!(quote, MIN_WITHDRAWAL_FEE);
        assert_ne!(
            quote.0, 0,
            "a degenerate zero median must never quote a free withdrawal"
        );
    }

    #[test]
    fn withdrawal_fee_quote_near_zero_median_is_also_floored() {
        // A tiny but nonzero median whose computed fee would round to below
        // the floor is still floored up to `MIN_WITHDRAWAL_FEE`, not left at
        // its (near-)free computed value.
        let median = FeeVote {
            max_fee_per_gas_wei: 1,
            usdt_per_eth_e6: 1,
        };
        let quote = withdrawal_fee_quote(&median).expect("tiny median must not overflow");
        assert_eq!(quote, MIN_WITHDRAWAL_FEE);
    }

    #[test]
    fn withdrawal_fee_quote_realistic_median_is_unaffected_by_the_floor() {
        // A realistic gas-market median (same as
        // `withdrawal_fee_quote_computes_expected_value`) computes well
        // above `MIN_WITHDRAWAL_FEE`, so the floor must not perturb it.
        let median = FeeVote {
            max_fee_per_gas_wei: 30_000_000_000,
            usdt_per_eth_e6: 3_000_000_000,
        };
        let quote = withdrawal_fee_quote(&median).expect("must not overflow for realistic input");
        assert_eq!(quote, UsdtAmount(38_880_000));
        assert!(quote.0 > MIN_WITHDRAWAL_FEE.0);
    }

    #[test]
    fn withdrawal_fee_quote_large_but_plausible_gas_price_does_not_overflow() {
        // A large but plausible fee spike: 5000 gwei max_fee_per_gas (far
        // above anything seen in practice, but nowhere near u64::MAX) and a
        // high ETH price, exercising the u128 intermediate without
        // overflowing.
        let median = FeeVote {
            max_fee_per_gas_wei: 5_000_000_000_000, // 5000 gwei
            usdt_per_eth_e6: 10_000_000_000,        // 10,000.000000 USDT/ETH
        };
        let quote = withdrawal_fee_quote(&median).expect("plausible fee spike must not overflow");
        assert!(quote.0 > 0);
    }
}
