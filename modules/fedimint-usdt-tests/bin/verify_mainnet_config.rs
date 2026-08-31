//! One-shot verifier for the addresses a MAINNET federation would be
//! configured with, run against real Ethereum mainnet over a public RPC.
//!
//! The module derives every deposit account counterfactually and offline
//! (`fedimint_usdt_common::derive_deposit_account`), from a hard-coded copy of
//! `ERC1967Proxy`'s creation bytecode. If that bytecode -- or the ABI encoding
//! around it -- disagrees by even one byte with what the *deployed*
//! `SimpleAccountFactory` actually `CREATE2`s, then users deposit USDT to
//! addresses the federation can never deploy an account at, and the funds are
//! unrecoverable. That failure is silent: nothing on the deposit path notices,
//! because both sides of the module agree with each other. The only way to
//! catch it is to ask the real factory. This binary does that.
//!
//! It is deliberately a `[[bin]]`, not a `#[test]`: it needs the public
//! internet and pins mainnet-specific addresses, so it must not run in CI (the
//! same reasoning as `capture-deposit-proof-fixtures`). Everything it does is
//! read-only -- `eth_call`, `eth_getCode`, `eth_getProof`,
//! `eth_getBlockByNumber`. It never signs or sends a transaction and never
//! touches a private key.
//!
//! Run with:
//!
//! ```sh
//! cargo run -p fedimint-usdt-tests --bin verify-mainnet-config
//! ```
//!
//! It exits non-zero (and says which check failed) on any disagreement.

use alloy::consensus::Header;
use alloy::eips::BlockId;
use alloy::primitives::{Address, B256, U256, keccak256};
use alloy::providers::{Provider, ProviderBuilder};
use alloy::rlp::Encodable as _;
use alloy::sol;
use alloy::sol_types::SolCall as _;
use anyhow::{Context as _, bail, ensure};
use fedimint_core::secp256k1::{PublicKey, Secp256k1, SecretKey};
use fedimint_usdt_common::{
    DepositProof, EvmAddress, USDT_BALANCES_SLOT, balances_storage_key, deposit_salt,
    derive_deposit_account, derive_pool_account, evm_address, pool_salt,
};
use fedimint_usdt_server::factory_bytecode::{derive_account_factory, derive_simple_account_impl};
use fedimint_usdt_server::proof::verify_deposit_proof;

/// Public Ethereum mainnet RPC (the same one `capture-deposit-proof-fixtures`
/// uses), chosen because it serves `eth_getProof` without an API key.
const RPC_URL: &str = "https://ethereum-rpc.publicnode.com";

/// Mainnet USDT (Tether).
const USDT_CONTRACT: &str = "0xdAC17F958D2ee523a2206206994597C13D831ec7";

/// The canonical ERC-4337 **v0.7** `EntryPoint`.
const ENTRY_POINT_V07: &str = "0x0000000071727De22E5E9d8BAf0edAc6f37da032";

/// The mainnet `SimpleAccountFactory` whose `accountImplementation` targets
/// [`ENTRY_POINT_V07`] -- the one a mainnet deployment of this module must be
/// configured with. Mainnet also carries `SimpleAccountFactory` deployments
/// wired to EntryPoint **v0.6**; those are verified below as a *negative*
/// control, because picking one of them is the realistic misconfiguration.
const FACTORY_V07: &str = "0x91E60e0613810449d098b0b5Ec8b51A0FE8c8985";

/// [`FACTORY_V07`]'s `accountImplementation()` (asserted against the chain).
const SIMPLE_ACCOUNT_IMPL_V07: &str = "0x68641de71cfEa5A5d0d29712449eE254bB1400C2";

/// An EntryPoint-v0.6 `SimpleAccountFactory` on mainnet, kept purely as the
/// negative control described on [`FACTORY_V07`].
const FACTORY_V06: &str = "0x9406Cc6185a346906296840746125a0E44976454";

/// [`FACTORY_V06`]'s `accountImplementation()` (asserted against the chain).
const SIMPLE_ACCOUNT_IMPL_V06: &str = "0x8abb13360b87Be5EeB1b98647A016adD927a136c";

/// Chainlink's ETH/USD aggregator on mainnet -- the module's compiled-in
/// `eth_usd_price_feed` default, re-checked here for code presence.
const ETH_USD_PRICE_FEED: &str = "0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419";

/// A heavily-funded USDT holder (Binance hot wallet) used for the storage-slot
/// proof: its balance slot is present in USDT's storage trie, so the proof is
/// an inclusion proof of a large non-zero value.
const USDT_HOLDER: &str = "0xF977814e90dA44bFA03b6295A0616a897441aceC";

sol! {
    #[sol(rpc)]
    interface ISimpleAccountFactory {
        function getAddress(address owner, uint256 salt) external view returns (address);
        function accountImplementation() external view returns (address);
    }
}

sol! {
    #[sol(rpc)]
    interface ISimpleAccount {
        function entryPoint() external view returns (address);
    }
}

sol! {
    #[sol(rpc)]
    interface IErc20BalanceOf {
        function balanceOf(address account) external view returns (uint256);
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let provider = ProviderBuilder::new().connect(RPC_URL).await?;

    let chain_id = provider.get_chain_id().await?;
    ensure!(
        chain_id == 1,
        "expected Ethereum mainnet (chain id 1), RPC reports {chain_id}"
    );
    println!(
        "RPC {RPC_URL} -> chain id {chain_id}, head {}",
        provider.get_block_number().await?
    );

    check_selectors()?;
    check_code_present(&provider).await?;
    let factory_v07 = check_factory_wiring(&provider).await?;
    check_derivation(&provider, factory_v07).await?;
    check_v06_negative_control(&provider).await?;
    check_self_deployed_factory(&provider).await?;
    check_storage_slot(&provider).await?;

    println!("\nALL CHECKS PASSED");
    Ok(())
}

/// Pins the two `SimpleAccountFactory` selectors by recomputing them from
/// their signatures, so a reader does not have to take either the ABI or a
/// quoted 4-byte constant on faith. `getAddress` and `createAccount` take the
/// *same* argument list and are easy to confuse; conflating them would make
/// this whole binary compare the module against the wrong function.
fn check_selectors() -> anyhow::Result<()> {
    let get_address = &keccak256(b"getAddress(address,uint256)")[..4];
    let create_account = &keccak256(b"createAccount(address,uint256)")[..4];
    println!("\n== function selectors ==");
    println!(
        "  getAddress(address,uint256)    = 0x{}",
        hex::encode(get_address)
    );
    println!(
        "  createAccount(address,uint256) = 0x{}",
        hex::encode(create_account)
    );

    ensure!(
        get_address == ISimpleAccountFactory::getAddressCall::SELECTOR,
        "sol!-generated getAddress selector disagrees with keccak of the signature"
    );
    ensure!(
        get_address == alloy::primitives::hex!("8cb84e18"),
        "getAddress(address,uint256) selector is not 0x8cb84e18"
    );
    ensure!(
        create_account == alloy::primitives::hex!("5fbfb9cf"),
        "createAccount(address,uint256) selector is not 0x5fbfb9cf"
    );
    Ok(())
}

/// Every address this module would be configured with must actually be a
/// contract on mainnet: a typo'd address is an EOA (or nothing), and `eth_call`
/// against an address with no code returns empty rather than reverting, which
/// is exactly the sort of quiet wrong answer that survives to deployment day.
async fn check_code_present(provider: &impl Provider) -> anyhow::Result<()> {
    println!("\n== eth_getCode (must all be contracts) ==");
    for (label, addr) in [
        ("usdt_contract", USDT_CONTRACT),
        ("entry_point (v0.7)", ENTRY_POINT_V07),
        ("account_factory (v0.7)", FACTORY_V07),
        ("simple_account_impl (v0.7)", SIMPLE_ACCOUNT_IMPL_V07),
        ("eth_usd_price_feed", ETH_USD_PRICE_FEED),
        ("account_factory (v0.6, control)", FACTORY_V06),
        (
            "simple_account_impl (v0.6, control)",
            SIMPLE_ACCOUNT_IMPL_V06,
        ),
    ] {
        let code = provider.get_code_at(addr.parse::<Address>()?).await?;
        ensure!(!code.is_empty(), "{label} {addr} has no code on mainnet");
        println!("  {label:<36} {addr}  {} bytes", code.len());
    }
    Ok(())
}

/// Confirms the factory/implementation/EntryPoint triple is internally
/// consistent *on chain*, rather than assuming the three constants above
/// belong together.
async fn check_factory_wiring(provider: &impl Provider) -> anyhow::Result<Address> {
    println!("\n== factory wiring ==");
    let factory_addr: Address = FACTORY_V07.parse()?;
    let factory = ISimpleAccountFactory::new(factory_addr, provider);
    let impl_addr = factory.accountImplementation().call().await?;
    println!("  {FACTORY_V07}.accountImplementation() = {impl_addr}");
    ensure!(
        impl_addr == SIMPLE_ACCOUNT_IMPL_V07.parse::<Address>()?,
        "factory's accountImplementation is not the pinned SIMPLE_ACCOUNT_IMPL_V07"
    );

    let entry_point = ISimpleAccount::new(impl_addr, provider)
        .entryPoint()
        .call()
        .await?;
    println!("  {impl_addr}.entryPoint()             = {entry_point}");
    ensure!(
        entry_point == ENTRY_POINT_V07.parse::<Address>()?,
        "implementation targets {entry_point}, not the v0.7 EntryPoint -- wrong factory"
    );
    Ok(factory_addr)
}

/// **The check this binary exists for.** For each of several group keys and
/// claim keys, the module's pure offline derivation must produce the exact
/// address the deployed factory's own `getAddress` reports for the same
/// `(owner, salt)`. Covers both salt paths: the per-deposit salt
/// ([`deposit_salt`]) and the federation's single fixed pool salt
/// ([`pool_salt`]).
async fn check_derivation(provider: &impl Provider, factory_addr: Address) -> anyhow::Result<()> {
    let factory = ISimpleAccountFactory::new(factory_addr, provider);
    let account_factory = EvmAddress(factory_addr.into_array());
    let simple_account_impl = EvmAddress(SIMPLE_ACCOUNT_IMPL_V07.parse::<Address>()?.into_array());

    println!("\n== derive_deposit_account vs SimpleAccountFactory.getAddress ==");
    println!("  account_factory      = {FACTORY_V07}");
    println!("  simple_account_impl  = {SIMPLE_ACCOUNT_IMPL_V07}");

    let mut mismatches = 0usize;
    for i in 0u8..4 {
        // Deterministic, publicly-known scalars: this binary only ever needs
        // *public* keys, and pinning them keeps its output reproducible.
        let group_pk = test_public_key(0x10 + i);
        let claim_pk = test_public_key(0xA0 + i);
        let owner = evm_address(&group_pk);
        let salt = deposit_salt(&claim_pk);

        let derived =
            derive_deposit_account(&group_pk, account_factory, simple_account_impl, &claim_pk);
        let onchain = factory
            .getAddress(Address::from(owner.0), U256::from_be_bytes(salt))
            .call()
            .await
            .context("factory.getAddress eth_call failed")?;

        report(
            &format!("deposit[{i}] owner={owner} salt=0x{}", hex::encode(salt)),
            derived,
            onchain,
            &mut mismatches,
        );
    }

    println!("\n== derive_pool_account vs SimpleAccountFactory.getAddress ==");
    println!(
        "  pool salt = 0x{} (fixed, keccak256(POOL_ACCOUNT_DOMAIN))",
        hex::encode(pool_salt())
    );
    for i in 0u8..2 {
        let group_pk = test_public_key(0x10 + i);
        let owner = evm_address(&group_pk);

        let derived = derive_pool_account(&group_pk, account_factory, simple_account_impl);
        let onchain = factory
            .getAddress(Address::from(owner.0), U256::from_be_bytes(pool_salt()))
            .call()
            .await
            .context("factory.getAddress eth_call failed")?;

        report(
            &format!("pool[{i}] owner={owner}"),
            derived,
            onchain,
            &mut mismatches,
        );
    }

    ensure!(
        mismatches == 0,
        "{mismatches} derived address(es) disagree with the on-chain factory -- deposits to \
         these addresses would be UNSWEEPABLE"
    );
    Ok(())
}

/// Negative control: the module's embedded `ERC1967Proxy` creation code is
/// specific to `@account-abstraction/contracts@0.7.0`. Pointing the same
/// derivation at an EntryPoint-v0.6 factory must *not* reproduce that
/// factory's `getAddress`. If it did, the positive result above would be
/// vacuous -- it would mean the derivation is insensitive to the very input
/// (which factory's proxy code) it is supposed to depend on.
async fn check_v06_negative_control(provider: &impl Provider) -> anyhow::Result<()> {
    println!("\n== negative control: same derivation against an EntryPoint-v0.6 factory ==");
    let factory_addr: Address = FACTORY_V06.parse()?;
    let factory = ISimpleAccountFactory::new(factory_addr, provider);
    let impl_addr = factory.accountImplementation().call().await?;
    ensure!(
        impl_addr == SIMPLE_ACCOUNT_IMPL_V06.parse::<Address>()?,
        "v0.6 control factory's accountImplementation moved"
    );
    let entry_point = ISimpleAccount::new(impl_addr, provider)
        .entryPoint()
        .call()
        .await?;
    println!("  {FACTORY_V06} -> impl {impl_addr} -> entryPoint {entry_point}");
    ensure!(
        entry_point != ENTRY_POINT_V07.parse::<Address>()?,
        "the v0.6 control factory unexpectedly targets the v0.7 EntryPoint"
    );

    let group_pk = test_public_key(0x10);
    let claim_pk = test_public_key(0xA0);
    let owner = evm_address(&group_pk);
    let salt = deposit_salt(&claim_pk);
    let derived = derive_deposit_account(
        &group_pk,
        EvmAddress(factory_addr.into_array()),
        EvmAddress(impl_addr.into_array()),
        &claim_pk,
    );
    let onchain = factory
        .getAddress(Address::from(owner.0), U256::from_be_bytes(salt))
        .call()
        .await?;
    println!("    module-derived = {}", Address::from(derived.0));
    println!("    on-chain       = {onchain}");
    if Address::from(derived.0) == onchain {
        bail!(
            "negative control FAILED: the module's v0.7 proxy code also reproduces a v0.6 \
             factory, so the mainnet match above proves nothing"
        );
    }
    println!("    differ, as expected (v0.6 factories embed a different ERC1967Proxy)");
    Ok(())
}

/// Reports what config-gen would ACTUALLY pick on mainnet if the operator set
/// nothing but `FM_USDT_ENTRY_POINT`: `usdt_gen_params_from_env` defaults
/// `account_factory` to the module's *own* `SimpleAccountFactory`, CREATE2'd
/// through the Arachnid proxy from a vendored bytecode and self-deployed by
/// the bootstrap observer -- **not** the canonical
/// [`FACTORY_V07`]. The two are different addresses and therefore produce
/// different deposit accounts, so which one a mainnet federation ends up on is
/// a live config decision, not a detail. Reports whether that self-derived
/// factory is already deployed on mainnet, and if it is, holds it to the same
/// `getAddress` equivalence as the canonical one.
async fn check_self_deployed_factory(provider: &impl Provider) -> anyhow::Result<()> {
    println!("\n== config-gen default: the module's OWN self-deployed factory ==");
    let entry_point = EvmAddress(ENTRY_POINT_V07.parse::<Address>()?.into_array());
    let derived_factory = derive_account_factory(entry_point);
    let derived_impl = derive_simple_account_impl(derived_factory);
    let factory_addr = Address::from(derived_factory.0);
    println!("  derive_account_factory(v0.7 EntryPoint) = {factory_addr}");
    println!(
        "  derive_simple_account_impl(that)        = {}",
        Address::from(derived_impl.0)
    );
    println!("  (canonical mainnet factory is         {FACTORY_V07})");

    let code = provider.get_code_at(factory_addr).await?;
    if code.is_empty() {
        println!(
            "  NOT DEPLOYED on mainnet yet ({} bytes of code) -- with no \
             FM_USDT_ACCOUNT_FACTORY override, a mainnet federation would self-deploy it before \
             handing out any deposit address",
            code.len()
        );
        return Ok(());
    }

    println!(
        "  already deployed ({} bytes); checking equivalence",
        code.len()
    );
    let onchain_impl = ISimpleAccountFactory::new(factory_addr, provider)
        .accountImplementation()
        .call()
        .await?;
    let onchain_entry_point = ISimpleAccount::new(onchain_impl, provider)
        .entryPoint()
        .call()
        .await?;
    println!("  on-chain accountImplementation()        = {onchain_impl}");
    println!("  on-chain impl.entryPoint()              = {onchain_entry_point}");
    ensure!(
        onchain_impl == Address::from(derived_impl.0),
        "the deployed self-factory's implementation is not the one the module predicts"
    );
    ensure!(
        onchain_entry_point == ENTRY_POINT_V07.parse::<Address>()?,
        "the deployed self-factory targets {onchain_entry_point}, not the v0.7 EntryPoint"
    );

    let group_pk = test_public_key(0x10);
    let claim_pk = test_public_key(0xA0);
    let owner = evm_address(&group_pk);
    let salt = deposit_salt(&claim_pk);
    let derived = derive_deposit_account(&group_pk, derived_factory, derived_impl, &claim_pk);
    let onchain = ISimpleAccountFactory::new(factory_addr, provider)
        .getAddress(Address::from(owner.0), U256::from_be_bytes(salt))
        .call()
        .await?;
    let mut mismatches = 0usize;
    report("self-deployed factory", derived, onchain, &mut mismatches);
    ensure!(
        mismatches == 0,
        "the module's self-derived factory disagrees with its own derivation"
    );
    Ok(())
}

/// Proves the module's `USDT_BALANCES_SLOT` assumption against the real
/// contract end-to-end: take a live `eth_getProof`, run the module's own
/// consensus verifier over it, and require the balance it *derives from the
/// trie* to equal what `balanceOf` reports at the same block. If USDT held
/// balances at some slot other than 2, the storage key would be wrong, the
/// proof would come back as an exclusion proof, and the verifier would return
/// 0 for a funded account -- so a nonzero, exactly-equal result is what makes
/// this conclusive.
async fn check_storage_slot(provider: &impl Provider) -> anyhow::Result<()> {
    println!("\n== eth_getProof / USDT balances storage slot ==");
    let usdt: Address = USDT_CONTRACT.parse()?;
    let holder_addr: Address = USDT_HOLDER.parse()?;
    let holder = EvmAddress(holder_addr.into_array());

    // A recent-but-settled block: well inside a full node's ~128-block state
    // window (so `eth_getProof` is served) and past any reorg.
    let block_number = provider.get_block_number().await? - 32;
    let block = provider
        .get_block(BlockId::number(block_number))
        .await?
        .context("block not found")?;
    let header: &Header = &block.header.inner;
    let mut header_rlp = Vec::new();
    header.encode(&mut header_rlp);
    let block_hash: B256 = block.header.hash;
    ensure!(
        keccak256(&header_rlp) == block_hash,
        "RLP-encoded header does not hash to the block hash"
    );
    println!("  block {block_number}  hash {block_hash}");

    let storage_key = B256::from(balances_storage_key(&holder));
    println!("  USDT_BALANCES_SLOT   = {USDT_BALANCES_SLOT}");
    println!("  holder               = {holder_addr}");
    println!("  keccak(pad32(holder) || pad32(slot)) = {storage_key}");

    let proof = provider
        .get_proof(usdt, vec![storage_key])
        .block_id(BlockId::number(block_number))
        .await
        .context("eth_getProof failed -- RPC does not serve it at this block")?;
    ensure!(
        proof.storage_proof.len() == 1,
        "expected one storage proof, got {}",
        proof.storage_proof.len()
    );
    let storage = &proof.storage_proof[0];
    println!(
        "  eth_getProof: {} account nodes, {} storage nodes, raw slot value {}",
        proof.account_proof.len(),
        storage.proof.len(),
        storage.value
    );

    let deposit_proof = DepositProof {
        block_number,
        header_rlp,
        account_proof: proof.account_proof.iter().map(|n| n.to_vec()).collect(),
        storage_proof: storage.proof.iter().map(|n| n.to_vec()).collect(),
    };
    let proven = verify_deposit_proof(
        &deposit_proof,
        block_hash.0,
        &EvmAddress(usdt.into_array()),
        &holder,
    )
    .context("the module's own verifier rejected a live mainnet proof")?;

    let via_call = IErc20BalanceOf::new(usdt, provider)
        .balanceOf(holder_addr)
        .block(BlockId::number(block_number))
        .call()
        .await
        .context("balanceOf eth_call failed")?;

    println!(
        "  proven balance (MPT walk, slot {USDT_BALANCES_SLOT}) = {}",
        proven.0
    );
    println!("  balanceOf() eth_call at same block             = {via_call}");
    ensure!(
        proven.0 > 0,
        "proven balance is zero -- slot {USDT_BALANCES_SLOT} is not USDT's balances mapping"
    );
    ensure!(
        U256::from(proven.0) == via_call,
        "proven balance {} != balanceOf {via_call}",
        proven.0
    );
    println!("  MATCH: slot {USDT_BALANCES_SLOT} is mainnet USDT's balances mapping");
    Ok(())
}

/// Prints one derived/on-chain pair and counts disagreements. Never returns
/// early: a full side-by-side table is far more diagnostic than the first
/// failure, and this binary's whole value is in what it actually printed.
fn report(label: &str, derived: EvmAddress, onchain: Address, mismatches: &mut usize) {
    let derived = Address::from(derived.0);
    if derived == onchain {
        println!("  OK       {label}\n           {derived}");
    } else {
        *mismatches += 1;
        println!("  MISMATCH {label}");
        println!("           module-derived = {derived}");
        println!("           on-chain       = {onchain}");
    }
}

/// A deterministic secp256k1 public key from a one-byte seed. Only the public
/// half is ever used (`evm_address`, `deposit_salt`); the scalar is a fixed
/// constant with no funds and no role beyond making the run reproducible.
fn test_public_key(seed: u8) -> PublicKey {
    let sk = SecretKey::from_slice(&[seed.max(1); 32]).expect("valid scalar");
    PublicKey::from_secret_key(&Secp256k1::new(), &sk)
}
