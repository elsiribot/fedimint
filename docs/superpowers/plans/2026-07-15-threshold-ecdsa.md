# Threshold-ECDSA Crate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A standalone workspace crate `fedimint-threshold-ecdsa` wrapping the audited `cggmp21` library, proving t-of-n DKG, threshold signing, and HD-derived per-deposit keys end-to-end in-memory — the phase-0 spike + phase-1 subsystem of the USDT-on-EVM design (`docs/superpowers/specs/2026-07-15-usdt-wallet-module-design.md`).

**Architecture:** Thin wrapper crate at `crypto/threshold-ecdsa`. It re-exports `cggmp21` protocol runners (keygen, aux-info, signing) and adds Fedimint-friendly helpers: secp256k1-crate interop (the workspace's canonical ECDSA types), HD child-key derivation for per-deposit addresses, and EVM address computation. Transport stays abstract (`round_based::Delivery`); tests use `round_based`'s in-memory simulation. Wiring into Fedimint's p2p/consensus is a **later plan** — this crate must not depend on fedimint-core.

**Tech Stack:** Rust (edition 2024, workspace-inherited), `cggmp21` 0.6.x (Kudelski-audited line), `round_based` (transport + sim), `secp256k1` (workspace), `sha3` (Keccak256, workspace), `tokio` (dev, tests).

## Global Constraints

- Workspace conventions (verified in this repo): package metadata all `{ workspace = true }` except `name`/`description`; `[lints] workspace = true`; unit tests in `src/tests.rs` (no `tests/` dir — matches `crypto/tbs`, `crypto/tpe`); crate dir `crypto/threshold-ecdsa`, package name `fedimint-threshold-ecdsa`; add to root `Cargo.toml` `members` (alphabetical) and `[workspace.dependencies]`.
- Set `publish = false` for now (CI `ci-crate-ownership.yml` checks crates.io ownership of publishable crates; flip to publishable in a follow-up once ownership is set up).
- **Keep this crate out of `fedimint-client-wasm`'s dependency graph** (wasm builds are selective; nothing to do as long as no client crate depends on it).
- **Never use `unwrap()` in non-test code** — `expect()` with a reason, or return `Result`.
- `cggmp21`'s **trusted-dealer share generation (`spof` feature) is test-only** — it reconstructs the full secret in one place. Production key material must only ever come from the DKG path. Never import `cggmp21::trusted_dealer` outside `#[cfg(test)]`.
- After code changes run `just format`; before each commit run `just clippy`.
- **API source-of-truth note:** the `cggmp21` snippets below were verified against docs.rs `cggmp21` 0.6.3 and the LFDT-Lockness README on 2026-07-15, but exact method names (e.g. the `round_based` sim helper, `KeyShare::from_parts`, `derive_child_public_key`, the HD feature name `hd-wallet` vs `hd-wallets`) may drift or differ in minor ways. **If a step fails to compile, the fix is to consult https://docs.rs/cggmp21 for the pinned version and adjust names while keeping the step's semantics** — do not change protocol semantics (threshold, execution IDs, digests) to make code compile.
- Full DKG + aux-info tests are computationally heavy (Paillier prime generation). Run this crate's tests with `--release`, and expect the DKG/aux tests to take on the order of minutes, not seconds.

---

### Task 1: Crate scaffolding + workspace wiring

**Files:**
- Create: `crypto/threshold-ecdsa/Cargo.toml`
- Create: `crypto/threshold-ecdsa/src/lib.rs`
- Modify: `Cargo.toml` (workspace root: `members` list + `[workspace.dependencies]`)

**Interfaces:**
- Consumes: nothing (first task).
- Produces: an empty compiling crate `fedimint-threshold-ecdsa`, with `cggmp21`, `round_based`, `secp256k1`, `sha3`, `anyhow`, `rand` available; type alias `Curve = cggmp21::supported_curves::Secp256k1` that all later tasks use.

- [ ] **Step 1: Add workspace dependencies to root `Cargo.toml`**

In `[workspace.dependencies]` (alphabetical order), add:

```toml
cggmp21 = { version = "0.6.3", features = ["hd-wallet"] }
round-based = { version = "0.4", features = ["derive"] }
```

(If `cargo` reports the `hd-wallet` feature doesn't exist, run `cargo add --dry-run cggmp21` or check docs.rs — the README calls it `hd-wallets`; use whichever exists. Update the `sign`/keygen builder method names accordingly if they differ.)

Also add the internal entry so later crates can consume it:

```toml
fedimint-threshold-ecdsa = { path = "./crypto/threshold-ecdsa", version = "=0.12.0-alpha" }
```

And add `"crypto/threshold-ecdsa"` to the `[workspace] members` list, keeping alphabetical order (after `"crypto/tbs"` / before or after `"crypto/tpe"` as alphabetics dictate: `derive-secret`, `hkdf`, `tbs`, `threshold-ecdsa`, `tpe`).

- [ ] **Step 2: Create `crypto/threshold-ecdsa/Cargo.toml`**

```toml
[package]
authors = { workspace = true }
description = "Threshold ECDSA (CGGMP21) wrapper for Fedimint federations"
edition = { workspace = true }
license = { workspace = true }
name = "fedimint-threshold-ecdsa"
publish = false
readme = { workspace = true }
repository = { workspace = true }
version = { workspace = true }

[lib]
name = "fedimint_threshold_ecdsa"
path = "src/lib.rs"

[dependencies]
anyhow = { workspace = true }
cggmp21 = { workspace = true }
rand = { workspace = true }
round-based = { workspace = true }
secp256k1 = { workspace = true }
sha3 = { workspace = true }

[dev-dependencies]
cggmp21 = { workspace = true, features = ["spof"] }
round-based = { workspace = true, features = ["sim"] }
tokio = { workspace = true, features = ["macros", "rt-multi-thread"] }

[lints]
workspace = true
```

(If `sha3` is not yet in `[workspace.dependencies]` — the workspace lock has it transitively — add `sha3 = "0.10.8"` there too. If the `round-based` sim feature is named `sim-async` for the async runner, enable that instead.)

- [ ] **Step 3: Create minimal `src/lib.rs`**

```rust
//! Threshold ECDSA for Fedimint federations, wrapping the audited
//! [`cggmp21`] implementation (CGGMP21 protocol, Kudelski-audited).
//!
//! This crate is transport-agnostic: protocol runners take a
//! [`round_based::MpcParty`], and the caller supplies message delivery.
//! It must not depend on fedimint-core; consensus/p2p wiring lives in the
//! server module that consumes this crate.

/// The only curve this crate supports.
pub type Curve = cggmp21::supported_curves::Secp256k1;

#[cfg(test)]
mod tests;
```

Also create an empty `crypto/threshold-ecdsa/src/tests.rs`:

```rust
// Tests are added task by task.
```

- [ ] **Step 4: Verify it compiles**

Run: `cargo check -q -p fedimint-threshold-ecdsa`
Expected: success, no warnings. (First run downloads/compiles cggmp21's dependency tree — takes a while.)

- [ ] **Step 5: Format, lint, commit**

```bash
just format
just clippy
git add Cargo.toml Cargo.lock crypto/threshold-ecdsa
git commit -m "feat(threshold-ecdsa): scaffold fedimint-threshold-ecdsa crate"
```

---

### Task 2: Distributed key generation (DKG) end-to-end

**Files:**
- Modify: `crypto/threshold-ecdsa/src/lib.rs`
- Modify: `crypto/threshold-ecdsa/src/tests.rs`

**Interfaces:**
- Consumes: `Curve` from Task 1.
- Produces:
  - `pub async fn run_keygen<M>(eid: cggmp21::ExecutionId<'_>, i: u16, t: u16, n: u16, rng: &mut (impl rand::RngCore + rand::CryptoRng), party: M) -> anyhow::Result<cggmp21::IncompleteKeyShare<Curve>>` where `M: round_based::Mpc<ProtocolMessage = cggmp21::keygen::ThresholdMsg<...>>` — in practice, take the concrete `MpcParty` type the compiler asks for; the signature that matters to later tasks is `(eid, i, t, n, rng, party) -> IncompleteKeyShare<Curve>`.
  - HD support is enabled at keygen (`hd_wallet(true)`), so derived-key signing (Task 5) works from these shares.

- [ ] **Step 1: Write the failing test**

Append to `src/tests.rs`:

```rust
use cggmp21::ExecutionId;
use rand::rngs::OsRng;

use crate::Curve;

const N: u16 = 4;
const T: u16 = 3;

#[tokio::test(flavor = "multi_thread")]
async fn dkg_produces_consistent_group_key() {
    let eid = ExecutionId::new(b"fedimint-threshold-ecdsa-test-dkg");

    let shares = round_based::sim::run_with_setup(
        (0..N).map(|_| OsRng),
        |i, party, mut rng| async move {
            crate::run_keygen(eid, i, T, N, &mut rng, party).await
        },
    )
    .expect("simulation failed")
    .into_iter()
    .collect::<anyhow::Result<Vec<_>>>()
    .expect("keygen failed");

    assert_eq!(shares.len(), usize::from(N));
    // All parties must agree on the group public key.
    let pk0 = shares[0].shared_public_key();
    for share in &shares[1..] {
        assert_eq!(share.shared_public_key(), pk0);
    }
}
```

(If the pinned `round_based` doesn't expose `sim::run_with_setup` but only the `Simulation` builder API, spawn one future per party with `simulation.add_party()` and `futures::future::try_join_all` — same semantics: n parties, full in-memory mesh.)

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --release -p fedimint-threshold-ecdsa dkg_produces -- --nocapture`
Expected: FAIL to compile with "cannot find function `run_keygen`".

- [ ] **Step 3: Implement `run_keygen`**

Add to `src/lib.rs`:

```rust
use anyhow::Context as _;

/// Run the CGGMP21 distributed key generation as party `i` of `n`,
/// with signing threshold `t`. HD derivation is always enabled so the
/// resulting share can sign for SLIP-10-derived child keys (per-deposit
/// addresses) without re-running DKG.
///
/// `eid` must be unique per protocol execution and identical across all
/// parties. The transport behind `party` must be authenticated, and
/// point-to-point messages encrypted (cggmp21 requirement).
pub async fn run_keygen<M>(
    eid: cggmp21::ExecutionId<'_>,
    i: u16,
    t: u16,
    n: u16,
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
    party: M,
) -> anyhow::Result<cggmp21::IncompleteKeyShare<Curve>>
where
    M: round_based::Mpc<ProtocolMessage = cggmp21::keygen::ThresholdMsg<
        Curve,
        cggmp21::security_level::SecurityLevel128,
        sha2::Sha256,
    >>,
{
    cggmp21::keygen::<Curve>(eid, i, n)
        .set_threshold(t)
        .hd_wallet(true)
        .start(rng, party)
        .await
        .context("cggmp21 keygen failed")
}
```

(The `where` bound's exact message type is what the compiler dictates — `ThresholdMsg`'s generic parameters follow the builder's defaults. If `sha2` needs to be a direct dependency for the bound, add `sha2 = { workspace = true }` to the crate and `sha2 = "0.10"` to workspace deps if absent.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --release -p fedimint-threshold-ecdsa dkg_produces -- --nocapture`
Expected: PASS (may take ~a minute in release).

- [ ] **Step 5: Format, lint, commit**

```bash
just format
just clippy
git add crypto/threshold-ecdsa Cargo.toml Cargo.lock
git commit -m "feat(threshold-ecdsa): DKG runner with in-memory e2e test"
```

---

### Task 3: Aux-info generation and full key share assembly

**Files:**
- Modify: `crypto/threshold-ecdsa/src/lib.rs`
- Modify: `crypto/threshold-ecdsa/src/tests.rs`

**Interfaces:**
- Consumes: `run_keygen` (Task 2).
- Produces:
  - `pub async fn run_aux_gen<M>(eid, i, n, pregenerated: cggmp21::PregeneratedPrimes, rng, party: M) -> anyhow::Result<cggmp21::key_share::AuxInfo>`
  - `pub fn assemble_key_share(core: cggmp21::IncompleteKeyShare<Curve>, aux: cggmp21::key_share::AuxInfo) -> anyhow::Result<cggmp21::KeyShare<Curve>>`
  - `pub type KeyShare = cggmp21::KeyShare<Curve>;` — the type all signing takes.

- [ ] **Step 1: Write the failing test**

Append to `src/tests.rs`:

```rust
#[tokio::test(flavor = "multi_thread")]
async fn aux_gen_and_assembly_yield_full_key_share() {
    let eid_keygen = ExecutionId::new(b"test-aux-keygen");
    let eid_aux = ExecutionId::new(b"test-aux-auxgen");

    let cores = round_based::sim::run_with_setup(
        (0..N).map(|_| OsRng),
        |i, party, mut rng| async move {
            crate::run_keygen(eid_keygen, i, T, N, &mut rng, party).await
        },
    )
    .expect("sim failed")
    .into_iter()
    .collect::<anyhow::Result<Vec<_>>>()
    .expect("keygen failed");

    let aux_infos = round_based::sim::run_with_setup(
        (0..N).map(|_| OsRng),
        |i, party, mut rng| async move {
            let primes = cggmp21::PregeneratedPrimes::generate(&mut rng);
            crate::run_aux_gen(eid_aux, i, N, primes, &mut rng, party).await
        },
    )
    .expect("sim failed")
    .into_iter()
    .collect::<anyhow::Result<Vec<_>>>()
    .expect("aux gen failed");

    for (core, aux) in cores.into_iter().zip(aux_infos) {
        let share = crate::assemble_key_share(core, aux).expect("assembly failed");
        // serde round-trip: shares must be storable in the guardian DB.
        let json = serde_json::to_string(&share).expect("serialize");
        let restored: crate::KeyShare = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored.shared_public_key(), share.shared_public_key());
    }
}
```

Add `serde_json = { workspace = true }` to `[dev-dependencies]` in the crate's `Cargo.toml`.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --release -p fedimint-threshold-ecdsa aux_gen_and_assembly -- --nocapture`
Expected: FAIL to compile with "cannot find function `run_aux_gen`".

- [ ] **Step 3: Implement `run_aux_gen`, `assemble_key_share`, `KeyShare` alias**

Add to `src/lib.rs`:

```rust
/// A guardian's complete signing share: DKG core share + auxiliary info
/// (Paillier keys, ring-Pedersen parameters). Serde-serializable for
/// storage in the guardian database.
pub type KeyShare = cggmp21::KeyShare<Curve>;

/// Run auxiliary-info generation (Paillier setup). `pregenerated` primes
/// are expensive to produce — generate them ahead of time (they are
/// consumed by this call).
pub async fn run_aux_gen<M>(
    eid: cggmp21::ExecutionId<'_>,
    i: u16,
    n: u16,
    pregenerated: cggmp21::PregeneratedPrimes,
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
    party: M,
) -> anyhow::Result<cggmp21::key_share::AuxInfo>
where
    M: round_based::Mpc<ProtocolMessage = cggmp21::aux_info_gen::Msg<
        cggmp21::security_level::SecurityLevel128,
        sha2::Sha256,
    >>,
{
    cggmp21::aux_info_gen(eid, i, n, pregenerated)
        .start(rng, party)
        .await
        .context("cggmp21 aux info generation failed")
}

/// Combine a DKG core share with aux info into a full, validated key share.
pub fn assemble_key_share(
    core: cggmp21::IncompleteKeyShare<Curve>,
    aux: cggmp21::key_share::AuxInfo,
) -> anyhow::Result<KeyShare> {
    cggmp21::KeyShare::from_parts((core, aux))
        .context("key share validation failed")
}
```

(`from_parts` comes from the `ValidateFromParts` machinery in `cggmp21::key_share` — if the method lives on the trait, import it; docs.rs `key_share` module shows the exact path.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --release -p fedimint-threshold-ecdsa aux_gen_and_assembly -- --nocapture`
Expected: PASS. This is the slowest test in the crate (per-party Paillier prime generation); minutes are normal.

- [ ] **Step 5: Format, lint, commit**

```bash
just format
just clippy
git add crypto/threshold-ecdsa Cargo.toml Cargo.lock
git commit -m "feat(threshold-ecdsa): aux info generation and key share assembly"
```

---

### Task 4: Threshold signing + secp256k1 interop

**Files:**
- Modify: `crypto/threshold-ecdsa/src/lib.rs`
- Modify: `crypto/threshold-ecdsa/src/tests.rs`

**Interfaces:**
- Consumes: `KeyShare` (Task 3).
- Produces:
  - `pub async fn run_signing<M>(eid, i: u16, signers: &[u16], share: &KeyShare, derivation_path: Option<&[u32]>, digest: [u8; 32], rng, party: M) -> anyhow::Result<secp256k1::ecdsa::Signature>` — `i` is this party's index *within `signers`*; `signers` lists the keygen indexes of the t participating parties.
  - `pub fn group_public_key(share: &KeyShare) -> anyhow::Result<secp256k1::PublicKey>`
  - Signatures returned are **low-s normalized** `secp256k1::ecdsa::Signature` (the workspace's canonical type), verified against the group key with the standard `secp256k1` crate.

- [ ] **Step 1: Write the failing test**

Append to `src/tests.rs`. Use the trusted dealer (test-only, `spof` feature) so this test doesn't re-run the slow DKG:

```rust
use sha3::{Digest as _, Keccak256};

fn dealer_shares() -> Vec<crate::KeyShare> {
    cggmp21::trusted_dealer::builder::<Curve>(N)
        .set_threshold(Some(T))
        .hd_wallet(true)
        .generate_shares(&mut OsRng)
        .expect("trusted dealer share generation failed")
}

#[tokio::test(flavor = "multi_thread")]
async fn threshold_signing_verifies_against_group_key() {
    let shares = dealer_shares();
    let eid = ExecutionId::new(b"test-signing");

    // Any t-subset may sign; pick keygen indexes [0, 1, 3].
    let signers: [u16; T as usize] = [0, 1, 3];
    let digest: [u8; 32] = Keccak256::digest(b"fedimint usdt withdrawal test").into();

    let signatures = round_based::sim::run_with_setup(
        signers.iter().map(|&keygen_i| (shares[usize::from(keygen_i)].clone(), OsRng)),
        |i, party, (share, mut rng)| {
            let signers = signers;
            async move {
                crate::run_signing(eid, i, &signers, &share, None, digest, &mut rng, party).await
            }
        },
    )
    .expect("sim failed")
    .into_iter()
    .collect::<anyhow::Result<Vec<_>>>()
    .expect("signing failed");

    let group_pk = crate::group_public_key(&shares[0]).expect("group key");
    let msg = secp256k1::Message::from_digest(digest);
    let secp = secp256k1::Secp256k1::verification_only();
    for sig in &signatures {
        secp.verify_ecdsa(&msg, sig, &group_pk).expect("signature must verify");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --release -p fedimint-threshold-ecdsa threshold_signing -- --nocapture`
Expected: FAIL to compile with "cannot find function `run_signing`".

- [ ] **Step 3: Implement signing and interop helpers**

Add to `src/lib.rs`:

```rust
/// Convert the group public key (a curve point) to the workspace's
/// canonical `secp256k1::PublicKey`.
pub fn group_public_key(share: &KeyShare) -> anyhow::Result<secp256k1::PublicKey> {
    let compressed = share.shared_public_key().to_bytes(true);
    secp256k1::PublicKey::from_slice(&compressed)
        .context("group public key is not a valid secp256k1 point")
}

fn convert_signature(
    sig: cggmp21::Signature<Curve>,
) -> anyhow::Result<secp256k1::ecdsa::Signature> {
    let mut compact = [0u8; 64];
    compact[..32].copy_from_slice(&sig.r.to_be_bytes());
    compact[32..].copy_from_slice(&sig.s.to_be_bytes());
    let mut sig = secp256k1::ecdsa::Signature::from_compact(&compact)
        .context("cggmp21 produced an invalid compact signature")?;
    // EVM (and the secp256k1 crate's verify) require low-s form.
    sig.normalize_s();
    Ok(sig)
}

/// Sign a 32-byte digest with a t-subset of guardians.
///
/// * `i` — this party's index within `signers` (0..t)
/// * `signers` — keygen indexes of the t participating parties (all
///   parties must pass the identical slice)
/// * `derivation_path` — optional SLIP-10 non-hardened path; when set,
///   the signature is valid for the derived child public key instead of
///   the group key
/// * `digest` — the prehashed message (e.g. keccak256 of an EVM tx)
#[allow(clippy::too_many_arguments)]
pub async fn run_signing<M>(
    eid: cggmp21::ExecutionId<'_>,
    i: u16,
    signers: &[u16],
    share: &KeyShare,
    derivation_path: Option<&[u32]>,
    digest: [u8; 32],
    rng: &mut (impl rand::RngCore + rand::CryptoRng),
    party: M,
) -> anyhow::Result<secp256k1::ecdsa::Signature>
where
    M: round_based::Mpc<ProtocolMessage = cggmp21::signing::Msg<
        Curve,
        sha2::Sha256,
    >>,
{
    let data = cggmp21::DataToSign::from_scalar(
        cggmp21::generic_ec::Scalar::from_be_bytes_mod_order(digest),
    );
    let mut builder = cggmp21::signing(eid, i, signers, share);
    if let Some(path) = derivation_path {
        builder = builder
            .set_derivation_path(path.iter().copied())
            .context("invalid derivation path")?;
    }
    let sig = builder
        .sign(rng, party, data)
        .await
        .context("cggmp21 signing failed")?;
    convert_signature(sig)
}
```

(If `DataToSign::from_scalar`/`Scalar::from_be_bytes_mod_order` differ, docs.rs shows the constructor — the requirement is signing a *prehashed* 32-byte digest, NOT re-hashing; `DataToSign::digest::<D>()` would double-hash. If `generic_ec` isn't re-exported by cggmp21, add `generic-ec = { workspace = true }` at the version cggmp21 uses.)

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --release -p fedimint-threshold-ecdsa threshold_signing -- --nocapture`
Expected: PASS.

- [ ] **Step 5: Add a negative test — fewer than t signers must fail**

Append to `src/tests.rs`:

```rust
#[tokio::test(flavor = "multi_thread")]
async fn signing_with_fewer_than_threshold_fails() {
    let shares = dealer_shares();
    let eid = ExecutionId::new(b"test-signing-subthreshold");
    let signers: [u16; 2] = [0, 1]; // t is 3
    let digest: [u8; 32] = Keccak256::digest(b"must not sign").into();

    let results = round_based::sim::run_with_setup(
        signers.iter().map(|&keygen_i| (shares[usize::from(keygen_i)].clone(), OsRng)),
        |i, party, (share, mut rng)| {
            let signers = signers;
            async move {
                crate::run_signing(eid, i, &signers, &share, None, digest, &mut rng, party).await
            }
        },
    );

    // Either the sim errors or every party's protocol run errors —
    // under no circumstances may a valid signature come back.
    if let Ok(outputs) = results {
        assert!(outputs.into_iter().all(|r| r.is_err()));
    }
}
```

- [ ] **Step 6: Run all crate tests**

Run: `cargo test --release -p fedimint-threshold-ecdsa`
Expected: all PASS.

- [ ] **Step 7: Format, lint, commit**

```bash
just format
just clippy
git add crypto/threshold-ecdsa Cargo.toml Cargo.lock
git commit -m "feat(threshold-ecdsa): threshold signing with secp256k1 interop"
```

---

### Task 5: HD-derived per-deposit keys + EVM addresses

**Files:**
- Modify: `crypto/threshold-ecdsa/src/lib.rs`
- Modify: `crypto/threshold-ecdsa/src/tests.rs`

**Interfaces:**
- Consumes: `KeyShare`, `run_signing` (Tasks 3–4).
- Produces:
  - `pub fn derived_public_key(share: &KeyShare, path: &[u32]) -> anyhow::Result<secp256k1::PublicKey>` — the child key a signature with `derivation_path: Some(path)` verifies against.
  - `pub fn evm_address(pk: &secp256k1::PublicKey) -> [u8; 20]` — keccak256(uncompressed_pubkey[1..])[12..], the standard Ethereum address.
  - Together these let the USDT module derive a per-deposit address from `(group key, user-specific path)` and later sign for it from the same shares — the design's tweaked-address requirement.

- [ ] **Step 1: Write the failing tests**

Append to `src/tests.rs`:

```rust
#[test]
fn evm_address_matches_known_vector() {
    // Private key 0x...01 -> the well-known address
    // 0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf
    let secp = secp256k1::Secp256k1::new();
    let mut sk_bytes = [0u8; 32];
    sk_bytes[31] = 1;
    let sk = secp256k1::SecretKey::from_slice(&sk_bytes).expect("valid key");
    let pk = sk.public_key(&secp);
    assert_eq!(
        crate::evm_address(&pk),
        <[u8; 20]>::try_from(
            hex::decode("7e5f4552091a69125d5dfcb7b8c2659029395bdf")
                .expect("valid hex")
                .as_slice()
        )
        .expect("20 bytes"),
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn derived_key_signing_verifies_against_derived_pubkey() {
    let shares = dealer_shares();
    let eid = ExecutionId::new(b"test-derived-signing");
    let signers: [u16; T as usize] = [0, 1, 2];
    let path: &[u32] = &[7, 42]; // e.g. (account, deposit-index)
    let digest: [u8; 32] = Keccak256::digest(b"deposit sweep").into();

    let signatures = round_based::sim::run_with_setup(
        signers.iter().map(|&keygen_i| (shares[usize::from(keygen_i)].clone(), OsRng)),
        |i, party, (share, mut rng)| {
            let signers = signers;
            async move {
                crate::run_signing(eid, i, &signers, &share, Some(path), digest, &mut rng, party)
                    .await
            }
        },
    )
    .expect("sim failed")
    .into_iter()
    .collect::<anyhow::Result<Vec<_>>>()
    .expect("signing failed");

    let child_pk = crate::derived_public_key(&shares[0], path).expect("derive");
    let group_pk = crate::group_public_key(&shares[0]).expect("group key");
    assert_ne!(child_pk, group_pk, "derived key must differ from group key");

    let msg = secp256k1::Message::from_digest(digest);
    let secp = secp256k1::Secp256k1::verification_only();
    for sig in &signatures {
        secp.verify_ecdsa(&msg, sig, &child_pk)
            .expect("must verify against the DERIVED key");
        assert!(
            secp.verify_ecdsa(&msg, sig, &group_pk).is_err(),
            "must NOT verify against the group key"
        );
    }
}
```

Add `hex = { workspace = true }` to `[dev-dependencies]`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --release -p fedimint-threshold-ecdsa evm_address derived_key -- --nocapture`
Expected: FAIL to compile with "cannot find function `evm_address`" / "`derived_public_key`".

- [ ] **Step 3: Implement `evm_address` and `derived_public_key`**

Add to `src/lib.rs`:

```rust
use sha3::{Digest as _, Keccak256};

/// The standard Ethereum address of a secp256k1 public key:
/// last 20 bytes of keccak256 over the 64-byte uncompressed point.
pub fn evm_address(pk: &secp256k1::PublicKey) -> [u8; 20] {
    let uncompressed = pk.serialize_uncompressed();
    let hash = Keccak256::digest(&uncompressed[1..]);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    address
}

/// Derive the child public key for `path` (SLIP-10, non-hardened).
/// A signature produced with `run_signing(.., Some(path), ..)` verifies
/// against this key.
pub fn derived_public_key(
    share: &KeyShare,
    path: &[u32],
) -> anyhow::Result<secp256k1::PublicKey> {
    let child = share
        .derive_child_public_key(path.iter().copied())
        .context("child key derivation failed")?;
    let compressed = child.public_key.to_bytes(true);
    secp256k1::PublicKey::from_slice(&compressed)
        .context("derived key is not a valid secp256k1 point")
}
```

(`derive_child_public_key` is the hd-wallet-feature method on key shares; docs.rs `key_share` module has the exact name/return type — the return exposes the child public point.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --release -p fedimint-threshold-ecdsa evm_address derived_key -- --nocapture`
Expected: PASS.

- [ ] **Step 5: Format, lint, commit**

```bash
just format
just clippy
git add crypto/threshold-ecdsa Cargo.toml Cargo.lock
git commit -m "feat(threshold-ecdsa): HD-derived deposit keys and EVM addresses"
```

---

### Task 6: Crate docs, full check, wrap-up

**Files:**
- Modify: `crypto/threshold-ecdsa/src/lib.rs` (module docs only)

**Interfaces:**
- Consumes: everything above.
- Produces: the finished crate. Public API consumed by later plans (module scaffolding, signing-session integration):
  - `Curve`, `KeyShare`
  - `run_keygen(eid, i, t, n, rng, party) -> IncompleteKeyShare<Curve>`
  - `run_aux_gen(eid, i, n, primes, rng, party) -> AuxInfo`
  - `assemble_key_share(core, aux) -> KeyShare`
  - `run_signing(eid, i, signers, share, derivation_path, digest, rng, party) -> secp256k1::ecdsa::Signature`
  - `group_public_key(share)`, `derived_public_key(share, path)`, `evm_address(pk)`

- [ ] **Step 1: Extend the crate-level rustdoc**

Replace the doc comment at the top of `src/lib.rs` with:

```rust
//! Threshold ECDSA for Fedimint federations, wrapping the audited
//! [`cggmp21`] implementation (CGGMP21 protocol, audited by Kudelski).
//!
//! # Model
//!
//! The federation runs DKG once ([`run_keygen`] + [`run_aux_gen`] +
//! [`assemble_key_share`]), yielding one [`KeyShare`] per guardian and a
//! single group secp256k1 key. Any `t` of `n` guardians co-produce a
//! standard ECDSA signature via [`run_signing`] — on-chain it is
//! indistinguishable from a single-key EOA signature.
//!
//! Per-deposit addresses use SLIP-10 non-hardened derivation: derive the
//! child key with [`derived_public_key`] (address via [`evm_address`]),
//! and sign for it later from the *same shares* by passing the
//! derivation path to [`run_signing`]. No per-deposit key material is
//! stored.
//!
//! # Transport
//!
//! Protocol runners are generic over [`round_based::Mpc`]; the caller
//! supplies message delivery (any authenticated `Stream`/`Sink` pair via
//! [`round_based::Delivery`]). All messages must be authenticated and
//! point-to-point messages encrypted. Tests use `round_based`'s
//! in-memory simulation; the Fedimint p2p wiring lives in the consuming
//! server module, not here.
//!
//! # Limitations
//!
//! * cggmp21 does not implement identifiable aborts: a stalled or
//!   malicious signer cannot be cryptographically blamed. Callers should
//!   apply per-peer round timeouts and retry with a different t-subset.
//! * `cggmp21::trusted_dealer` (behind the `spof` feature) reconstructs
//!   the full secret in one place and is used in this crate's tests
//!   only. Production shares must come from DKG.
```

- [ ] **Step 2: Full test run + docs build**

Run: `cargo test --release -p fedimint-threshold-ecdsa`
Expected: all PASS.

Run: `cargo doc -q -p fedimint-threshold-ecdsa --no-deps`
Expected: success, no rustdoc warnings.

- [ ] **Step 3: Final lint and commit**

```bash
just format
just final-lint
git add crypto/threshold-ecdsa
git commit -m "docs(threshold-ecdsa): crate-level documentation"
```

Expected: `just final-lint` passes. If it flags anything (e.g. semgrep, doc formatting), fix and amend.

---

## Out of scope for this plan (next plans in the series)

1. **Fedimint transport wiring** — implement `round_based::Delivery` over the guardian p2p layer (authenticated/encrypted links), session management, per-peer timeouts, signer-subset rotation on stall. This is where the "interactive MPC ↔ consensus" risk is retired.
2. **DKG-at-setup integration** — running keygen/aux-gen during federation setup (`distributed_gen`), storing `KeyShare` in guardian config/DB.
3. **Module scaffolding** (`fedimint-usdt-common`/`-server`/`-client`), EVM adapter, deposit path, ERC-4337 integration, consolidation, withdrawal — per the design doc's phases.
