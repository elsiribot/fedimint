# Phase 2: Exchange-Round Transport Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Add a transport abstraction to `fedimint-threshold-ecdsa` that drives any cggmp21 protocol (keygen, aux-gen, signing) over synchronous all-to-all byte-exchange rounds with per-recipient-encrypted point-to-point messages — the only transport shape Fedimint offers at both config-gen (`PeerHandleOps::exchange_bytes`) and runtime (consensus items). Proven by re-running DKG + signing over this transport and verifying equivalence with Phase 1's native async path.

**Architecture:** Three units. (1) `RoundExchange` trait — one synchronous all-to-all byte round; an in-memory mesh implementation for tests. (2) `EncryptedRoundCodec` — packs a cggmp21 round's outgoing messages into one byte payload, encrypting each point-to-point message to its recipient via ephemeral-static ECDH + HKDF + ChaCha20-Poly1305 (the established fedimint idiom), and unpacks/decrypts incoming payloads. (3) `drive_over_exchange` — pumps a cggmp21 `state-machine`-feature sync `StateMachine`, batching its outgoing messages per round, exchanging, and feeding received messages back. The crate stays free of `fedimint-core`; the `PeerHandleOps`/consensus adapters that implement `RoundExchange` in production live in later phases (Phase 3/6).

**Tech stack:** Rust edition 2024; `cggmp21` 0.6.3 with the **`state-machine`** feature added; `round-based` 0.4.1 `state_machine` module; `secp256k1` ecdh (already available, no feature needed); `fedimint-hkdf` (Sha256) + `fedimint-aead` (ChaCha20-Poly1305) for per-recipient encryption; `tokio` for the in-memory mesh; `serde` + a binary format for message serialization.

## Global Constraints

- Crate: `fedimint-threshold-ecdsa` at `crypto/threshold-ecdsa`. **MUST NOT depend on `fedimint-core`.** New workspace deps needed: `fedimint-hkdf` and `fedimint-aead` (both already `[workspace.dependencies]` — verify names `fedimint-hkdf`/`fedimint-aead`), and a binary serde format for MPC messages (prefer an existing workspace dep — check for `bincode`; if absent, use `postcard` or add `bincode`; the format only needs to round-trip serde types and is wrapped in opaque `Vec<u8>`).
- Add the **`state-machine`** feature to the workspace `cggmp21` entry (alongside `hd-wallet`, `hd-slip10`, `curve-secp256k1`).
- Never `unwrap()`/`panic!` in non-test code — `expect()` with a reason or return `Result`.
- Party identity in this phase is the round-based **`PartyIndex = u16`** in `0..n`. `PeerId` mapping is a later-phase adapter concern — do NOT introduce `PeerId` here.
- Encryption idiom (match `modules/fedimint-lnv2-common/src/tweak.rs`): sender makes an ephemeral `secp256k1::Keypair`, computes `ecdh::SharedSecret::new(&recipient_static_pk, &ephemeral_sk).secret_bytes()` → `[u8;32]`; recipient recomputes `SharedSecret::new(&ephemeral_pk, &recipient_sk)`. Stretch the 32-byte secret through `fedimint_hkdf::Hkdf::<Sha256>::new(&secret, Some(salt)).derive::<32>(info)` → `ring::aead::UnboundKey::new(&CHACHA20_POLY1305, &key)` → `LessSafeKey` → `fedimint_aead::encrypt`. Broadcast messages are sent in clear (they are broadcast anyway); only `MessageDestination::OneParty` messages are encrypted.
- Tests run in `--release` (cggmp21 math); DKG/aux tests take minutes — use long timeouts, this is not a hang.
- `just format` after changes; `cargo clippy -q --locked --offline -p fedimint-threshold-ecdsa --all-targets -- -D warnings` before each commit. (`just lint`'s pre-commit-hook step is environmentally broken in this checkout — use the direct clippy invocation.)
- **API source-of-truth:** the `round_based`/`cggmp21` snippets below were verified against round-based 0.4.1 and cggmp21 0.6.3 sources on 2026-07-16. On compile failure, consult the vendored sources under `~/.cargo/registry/src/*/{round-based-0.4.1,cggmp21-0.6.3,cggmp21-keygen-0.5.0}` and adjust NAMES to match; never change protocol semantics (round structure, no double-encryption of broadcast, digest handling).

## Verified API reference (from vendored sources, 2026-07-16)

`round_based::state_machine` (feature `state-machine`):
```rust
pub trait StateMachine { type Output; type Msg;
    fn proceed(&mut self) -> ProceedResult<Self::Output, Self::Msg>;
    fn received_msg(&mut self, msg: Incoming<Self::Msg>) -> Result<(), Incoming<Self::Msg>>;
}
pub enum ProceedResult<O, M> { SendMsg(Outgoing<M>), NeedsOneMoreMessage, Output(O), Yielded, Error(ExecutionError) }
```
Contract: `received_msg` only after `proceed()` returned `NeedsOneMoreMessage`, then call `proceed()` again. `proceed()` after done → `Error`.
```rust
pub struct Incoming<M> { pub id: MsgId /*u64*/, pub sender: PartyIndex /*u16*/, pub msg_type: MessageType, pub msg: M }
pub enum MessageType { Broadcast, P2P }
pub struct Outgoing<M> { pub recipient: MessageDestination, pub msg: M }
pub enum MessageDestination { AllParties, OneParty(PartyIndex /*u16*/) }
```
cggmp21 sync entry points (feature `state-machine`), all return `impl StateMachine`:
- keygen: `cggmp21::keygen::<E>(eid,i,n).set_threshold(t).hd_wallet(true).into_state_machine(&mut rng)` → `Output=Result<CoreKeyShare<E>,KeygenError>`, `Msg=cggmp21::keygen::ThresholdMsg<E,L,D>`.
- aux: `cggmp21::aux_info_gen(eid,i,n,primes).into_state_machine(&mut rng)` → `Output=Result<AuxInfo,KeyRefreshError>`, `Msg=cggmp21::key_refresh::AuxOnlyMsg<D,L>` (note `<D,L>` order).
- signing: `cggmp21::signing(eid,i,signers,share).sign_sync(&mut rng, data)` → `Output=Result<Signature<E>,SigningError>`, `Msg=cggmp21::signing::msg::Msg<E,D>`.

`rng` is borrowed `&mut` for the state machine's whole lifetime — keep it alive alongside.

## File structure

- `crypto/threshold-ecdsa/src/transport/mod.rs` — `RoundExchange` trait, `PartyIndex` re-export, module glue.
- `crypto/threshold-ecdsa/src/transport/mesh.rs` — `InMemoryMesh` test transport (n endpoints, all-to-all).
- `crypto/threshold-ecdsa/src/transport/codec.rs` — `EncryptedRoundCodec`, round-packet types, ECDH/HKDF/AEAD.
- `crypto/threshold-ecdsa/src/transport/driver.rs` — `drive_over_exchange`.
- `crypto/threshold-ecdsa/src/lib.rs` — `pub mod transport;` + re-exports.
- `crypto/threshold-ecdsa/src/tests.rs` — extend with a transport-driven keygen+sign acceptance test.

---

### Task 1: `RoundExchange` trait + in-memory mesh

**Files:**
- Create: `crypto/threshold-ecdsa/src/transport/mod.rs`, `crypto/threshold-ecdsa/src/transport/mesh.rs`
- Modify: `crypto/threshold-ecdsa/src/lib.rs` (add `pub mod transport;`)

**Interfaces produced:**
```rust
pub type PartyIndex = u16;
/// One synchronous all-to-all byte-exchange round among `n` parties.
#[async_trait::async_trait]
pub trait RoundExchange: Send {
    fn party_index(&self) -> PartyIndex;
    fn n(&self) -> u16;
    /// Broadcast `ours`; return every party's payload indexed by party 0..n
    /// (our own payload in slot `party_index()`).
    async fn exchange(&mut self, ours: Vec<u8>) -> anyhow::Result<Vec<Vec<u8>>>;
}
/// Build `n` connected in-memory endpoints (test transport).
pub fn in_memory_mesh(n: u16) -> Vec<InMemoryMesh>; // each impls RoundExchange
```

- [ ] **Step 1: Add deps + module declaration**

In `crypto/threshold-ecdsa/Cargo.toml` add to `[dependencies]`: `async-trait = { workspace = true }`, `tokio = { workspace = true, features = ["sync"] }`. (Verify `async-trait` is a workspace dep; it is used widely in the repo.) In `src/lib.rs` add `pub mod transport;` near the top (after the `Curve` alias).

- [ ] **Step 2: Write the failing test** (put in `mesh.rs` under `#[cfg(test)] mod tests`)

```rust
#[tokio::test(flavor = "multi_thread")]
async fn mesh_exchanges_all_to_all() {
    let mut ends = crate::transport::in_memory_mesh(4);
    // Each party runs one round concurrently, broadcasting its index as bytes.
    let handles: Vec<_> = ends.drain(..).map(|mut e| tokio::spawn(async move {
        let got = e.exchange(vec![e.party_index() as u8]).await.expect("exchange");
        (e.party_index(), got)
    })).collect();
    for h in handles {
        let (i, got) = h.await.expect("join");
        assert_eq!(got.len(), 4, "party {i} must receive n payloads");
        for (j, payload) in got.iter().enumerate() {
            assert_eq!(payload, &vec![j as u8], "slot j holds party j's payload");
        }
    }
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `cargo test -q -p fedimint-threshold-ecdsa mesh_exchanges -- --nocapture`
Expected: FAIL to compile (`in_memory_mesh` not found).

- [ ] **Step 4: Implement `mod.rs` (trait) and `mesh.rs`**

`transport/mod.rs`:
```rust
//! Transport for driving cggmp21 protocols over synchronous all-to-all
//! byte-exchange rounds. See [`drive_over_exchange`].
mod codec;
mod driver;
mod mesh;

pub use codec::EncryptedRoundCodec;
pub use driver::drive_over_exchange;
pub use mesh::{in_memory_mesh, InMemoryMesh};

pub type PartyIndex = u16;

#[async_trait::async_trait]
pub trait RoundExchange: Send {
    fn party_index(&self) -> PartyIndex;
    fn n(&self) -> u16;
    async fn exchange(&mut self, ours: Vec<u8>) -> anyhow::Result<Vec<Vec<u8>>>;
}
```
(Add `pub use codec::*` etc. only after those files exist — Tasks 2/3 create them. To keep Task 1 compiling, temporarily declare only `mod mesh;` + the trait, and add `mod codec; mod driver;` and their re-exports in Tasks 2/3. Alternatively create empty `codec.rs`/`driver.rs` stubs now.)

`transport/mesh.rs` — one mpsc channel per ordered pair; `exchange` sends `ours` to every other party's inbound channel then receives one payload from each:
```rust
use anyhow::Context as _;
use tokio::sync::mpsc;

use super::{PartyIndex, RoundExchange};

pub struct InMemoryMesh {
    index: PartyIndex,
    n: u16,
    // senders[j] delivers to party j's inbox; inbox receives (sender_index, bytes)
    senders: Vec<mpsc::UnboundedSender<(PartyIndex, Vec<u8>)>>,
    inbox: mpsc::UnboundedReceiver<(PartyIndex, Vec<u8>)>,
}

pub fn in_memory_mesh(n: u16) -> Vec<InMemoryMesh> {
    let mut senders = Vec::with_capacity(n as usize);
    let mut inboxes = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let (tx, rx) = mpsc::unbounded_channel();
        senders.push(tx);
        inboxes.push(rx);
    }
    inboxes.into_iter().enumerate().map(|(i, inbox)| InMemoryMesh {
        index: i as PartyIndex,
        n,
        senders: senders.clone(),
        inbox,
    }).collect()
}

#[async_trait::async_trait]
impl RoundExchange for InMemoryMesh {
    fn party_index(&self) -> PartyIndex { self.index }
    fn n(&self) -> u16 { self.n }

    async fn exchange(&mut self, ours: Vec<u8>) -> anyhow::Result<Vec<Vec<u8>>> {
        for j in 0..self.n {
            if j != self.index {
                self.senders[j as usize]
                    .send((self.index, ours.clone()))
                    .map_err(|_| anyhow::anyhow!("mesh peer {j} dropped"))?;
            }
        }
        let mut slots: Vec<Option<Vec<u8>>> = vec![None; self.n as usize];
        slots[self.index as usize] = Some(ours);
        for _ in 0..(self.n - 1) {
            let (sender, bytes) = self.inbox.recv().await.context("mesh closed")?;
            slots[sender as usize] = Some(bytes);
        }
        slots.into_iter().enumerate()
            .map(|(j, s)| s.with_context(|| format!("missing payload from party {j}")))
            .collect()
    }
}
```
(If `mod.rs` re-exports `codec`/`driver` before they exist, create empty stub files `codec.rs`/`driver.rs` containing just a doc comment so the module tree compiles.)

- [ ] **Step 5: Run test to verify it passes**

Run: `cargo test -q -p fedimint-threshold-ecdsa mesh_exchanges -- --nocapture`
Expected: PASS.

- [ ] **Step 6: Format, lint, commit**

```bash
just format
cargo clippy -q --locked --offline -p fedimint-threshold-ecdsa --all-targets -- -D warnings
git add crypto/threshold-ecdsa Cargo.toml Cargo.lock
git commit -m "feat(threshold-ecdsa): RoundExchange trait and in-memory mesh"
```

---

### Task 2: `EncryptedRoundCodec`

**Files:**
- Create/replace: `crypto/threshold-ecdsa/src/transport/codec.rs`
- Modify: `crypto/threshold-ecdsa/Cargo.toml` (deps), `transport/mod.rs` (re-export)

**Interfaces produced:**
```rust
/// One party's cryptographic material for encrypting p2p round messages.
pub struct EncryptedRoundCodec {
    my_index: PartyIndex,
    my_secret: secp256k1::SecretKey,
    party_pubkeys: Vec<secp256k1::PublicKey>, // indexed by PartyIndex, includes self
}
impl EncryptedRoundCodec {
    pub fn new(my_index: PartyIndex, my_secret: secp256k1::SecretKey,
               party_pubkeys: Vec<secp256k1::PublicKey>) -> Self;
    /// Serialize + encrypt one round's outgoing messages into a wire payload.
    pub fn seal_round<M: serde::Serialize>(
        &self, broadcast: Option<&M>, p2p: &BTreeMap<PartyIndex, M>,
    ) -> anyhow::Result<Vec<u8>>;
    /// Decrypt + deserialize a payload from `sender` into its messages for us.
    pub fn open_round<M: serde::de::DeserializeOwned>(
        &self, sender: PartyIndex, payload: &[u8],
    ) -> anyhow::Result<OpenedRound<M>>;
}
pub struct OpenedRound<M> { pub broadcast: Option<M>, pub p2p_to_me: Option<M> }
```

The wire packet (serde-serializable, binary-encoded):
```rust
#[derive(serde::Serialize, serde::Deserialize)]
struct RoundPacket {
    broadcast: Option<Vec<u8>>,           // plaintext serialized M
    // recipient PartyIndex -> ECIES box { ephemeral_pk: [u8;33], ct: Vec<u8> }
    p2p: BTreeMap<PartyIndex, EciesBox>,
}
#[derive(serde::Serialize, serde::Deserialize)]
struct EciesBox { ephemeral_pk: [u8; 33], ciphertext: Vec<u8> }
```

- [ ] **Step 1: Add deps**

`Cargo.toml` `[dependencies]`: `fedimint-hkdf = { workspace = true }`, `fedimint-aead = { workspace = true }`, `serde = { workspace = true, features = ["derive"] }`, and a binary codec — check `grep -n '^bincode' Cargo.toml` at repo root; if present add `bincode = { workspace = true }`, else `postcard = { workspace = true }` (add to root workspace deps if missing: `postcard = { version = "1", features = ["use-std"] }`). `secp256k1 = { workspace = true }` is already present.

- [ ] **Step 2: Write failing tests** (in `codec.rs` `#[cfg(test)]`)

```rust
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use std::collections::BTreeMap;
use super::EncryptedRoundCodec;

fn keypairs(n: u16) -> (Vec<SecretKey>, Vec<PublicKey>) {
    let secp = Secp256k1::new();
    let sks: Vec<_> = (0..n).map(|i| {
        let mut b = [1u8; 32]; b[31] = (i + 1) as u8; SecretKey::from_slice(&b).unwrap()
    }).collect();
    let pks = sks.iter().map(|sk| sk.public_key(&secp)).collect();
    (sks, pks)
}

#[test]
fn broadcast_and_p2p_round_trip() {
    let (sks, pks) = keypairs(3);
    let codec0 = EncryptedRoundCodec::new(0, sks[0], pks.clone());
    let codec1 = EncryptedRoundCodec::new(1, sks[1], pks.clone());
    let mut p2p = BTreeMap::new();
    p2p.insert(1u16, "secret-for-1".to_string());
    p2p.insert(2u16, "secret-for-2".to_string());
    let payload = codec0.seal_round(Some(&"hello-all".to_string()), &p2p).expect("seal");
    let opened = codec1.open_round::<String>(0, &payload).expect("open");
    assert_eq!(opened.broadcast.as_deref(), Some("hello-all"));
    assert_eq!(opened.p2p_to_me.as_deref(), Some("secret-for-1"));
}

#[test]
fn wrong_recipient_cannot_read_others_p2p() {
    let (sks, pks) = keypairs(3);
    let codec0 = EncryptedRoundCodec::new(0, sks[0], pks.clone());
    let codec2 = EncryptedRoundCodec::new(2, sks[2], pks.clone());
    let mut p2p = BTreeMap::new();
    p2p.insert(1u16, "only-for-1".to_string());
    let payload = codec0.seal_round::<String>(None, &p2p).expect("seal");
    let opened = codec2.open_round::<String>(0, &payload).expect("open");
    assert!(opened.p2p_to_me.is_none(), "party 2 has no p2p; cannot read party 1's box");
}

#[test]
fn tampered_ciphertext_is_rejected() {
    let (sks, pks) = keypairs(2);
    let codec0 = EncryptedRoundCodec::new(0, sks[0], pks.clone());
    let codec1 = EncryptedRoundCodec::new(1, sks[1], pks.clone());
    let mut p2p = BTreeMap::new();
    p2p.insert(1u16, "x".to_string());
    let mut payload = codec0.seal_round::<String>(None, &p2p).expect("seal");
    *payload.last_mut().unwrap() ^= 0xff; // flip a byte
    assert!(codec1.open_round::<String>(0, &payload).is_err(), "AEAD tag must reject tamper");
}
```

- [ ] **Step 3: Run to verify fail** — `cargo test -q -p fedimint-threshold-ecdsa codec:: -- --nocapture` → FAIL (compile).

- [ ] **Step 4: Implement `codec.rs`**

Serialize each `M` with the chosen binary codec into `Vec<u8>`; for each p2p recipient: ephemeral keypair → ECDH with recipient pubkey → HKDF-Sha256 derive 32-byte key (salt = fixed domain string `b"fedimint-threshold-ecdsa/round-p2p/v0"`, info = recipient index bytes) → `fedimint_aead::encrypt(serialized, &key)` (prepends nonce). Store `{ephemeral_pk (33-byte compressed), ciphertext}`. `open_round`: for our own `p2p[my_index]` box, recompute ECDH from `ephemeral_pk` + our secret, derive key, `fedimint_aead::decrypt`. Deserialize. Broadcast is plaintext-serialized.

```rust
use anyhow::Context as _;
use fedimint_hkdf::hashes::Sha256;
use fedimint_hkdf::Hkdf;
use ring::aead::{LessSafeKey, UnboundKey, CHACHA20_POLY1305};
use secp256k1::{ecdh, Keypair, PublicKey, Secp256k1, SecretKey};
use std::collections::BTreeMap;

use super::PartyIndex;

const P2P_SALT: &[u8] = b"fedimint-threshold-ecdsa/round-p2p/v0";

fn aead_key(shared: [u8; 32], recipient: PartyIndex) -> anyhow::Result<LessSafeKey> {
    let key_bytes = Hkdf::<Sha256>::new(&shared, Some(P2P_SALT))
        .derive::<32>(&recipient.to_be_bytes());
    let unbound = UnboundKey::new(&CHACHA20_POLY1305, &key_bytes)
        .map_err(|_| anyhow::anyhow!("aead key construction failed"))?;
    Ok(LessSafeKey::new(unbound))
}
// seal_round: bincode/postcard-serialize M; per recipient do ecdh + aead_key + fedimint_aead::encrypt.
// open_round: look up p2p.get(&my_index); recompute shared = ecdh::SharedSecret::new(&eph_pk, &my_secret);
//             fedimint_aead::decrypt(&mut ct, &key); deserialize.
```
(Use `serde_encode`/`serde_decode` helpers wrapping the chosen binary codec. `fedimint_aead::decrypt` takes `&mut [u8]` and returns a slice; clone the ciphertext into a mutable buffer first.)

- [ ] **Step 5: Run to verify pass** — `cargo test -q -p fedimint-threshold-ecdsa codec:: -- --nocapture` → PASS (3 tests).

- [ ] **Step 6: Add `mod codec;` + `pub use codec::{EncryptedRoundCodec, OpenedRound};` to `mod.rs`, format, lint, commit**

```bash
just format
cargo clippy -q --locked --offline -p fedimint-threshold-ecdsa --all-targets -- -D warnings
git add crypto/threshold-ecdsa Cargo.toml Cargo.lock
git commit -m "feat(threshold-ecdsa): per-recipient-encrypted round codec"
```

---

### Task 3: `drive_over_exchange`

**Files:**
- Create/replace: `crypto/threshold-ecdsa/src/transport/driver.rs`
- Modify: `transport/mod.rs` (re-export)

**Interface produced:**
```rust
/// Drive a cggmp21 sync state machine to completion over a RoundExchange,
/// encrypting point-to-point messages per recipient via the codec.
pub async fn drive_over_exchange<SM>(
    mut sm: SM,
    codec: &EncryptedRoundCodec,
    exchange: &mut dyn RoundExchange,
) -> anyhow::Result<SM::Output>
where
    SM: round_based::state_machine::StateMachine,
    SM::Msg: serde::Serialize + serde::de::DeserializeOwned;
```

**Driver algorithm (the load-bearing logic):** buffer the state machine's outgoing messages until it asks for input with an empty incoming queue — that is the round boundary; then exchange, refill the incoming queue, and drain it.

```rust
use anyhow::{anyhow, Context as _};
use round_based::state_machine::{ProceedResult, StateMachine};
use round_based::{Incoming, MessageDestination, MessageType, Outgoing};
use std::collections::{BTreeMap, VecDeque};

use super::{EncryptedRoundCodec, RoundExchange};

pub async fn drive_over_exchange<SM>(
    mut sm: SM, codec: &EncryptedRoundCodec, exchange: &mut dyn RoundExchange,
) -> anyhow::Result<SM::Output>
where SM: StateMachine, SM::Msg: serde::Serialize + serde::de::DeserializeOwned {
    let me = exchange.party_index();
    let n = exchange.n();
    let mut broadcast_out: Option<SM::Msg> = None;
    let mut p2p_out: BTreeMap<u16, SM::Msg> = BTreeMap::new();
    let mut incoming: VecDeque<Incoming<SM::Msg>> = VecDeque::new();
    let mut next_id: u64 = 0;

    loop {
        match sm.proceed() {
            ProceedResult::Output(out) => return Ok(out),
            ProceedResult::Error(err) => return Err(anyhow!("mpc state machine failed: {err}")),
            ProceedResult::Yielded => continue,
            ProceedResult::SendMsg(Outgoing { recipient, msg }) => match recipient {
                MessageDestination::AllParties => broadcast_out = Some(msg),
                MessageDestination::OneParty(j) => { p2p_out.insert(j, msg); }
            },
            ProceedResult::NeedsOneMoreMessage => {
                if let Some(msg) = incoming.pop_front() {
                    sm.received_msg(msg).map_err(|_| anyhow!("state machine rejected message"))?;
                    continue;
                }
                // Round boundary: exchange our buffered outgoing, refill incoming.
                let payload = codec.seal_round(broadcast_out.as_ref(), &p2p_out)
                    .context("sealing round payload")?;
                broadcast_out = None;
                p2p_out.clear();
                let all = exchange.exchange(payload).await.context("round exchange")?;
                for sender in 0..n {
                    if sender == me { continue; }
                    let opened = codec.open_round::<SM::Msg>(sender, &all[sender as usize])
                        .with_context(|| format!("opening round payload from party {sender}"))?;
                    if let Some(b) = opened.broadcast {
                        incoming.push_back(Incoming { id: next_id, sender, msg_type: MessageType::Broadcast, msg: b });
                        next_id += 1;
                    }
                    if let Some(p) = opened.p2p_to_me {
                        incoming.push_back(Incoming { id: next_id, sender, msg_type: MessageType::P2P, msg: p });
                        next_id += 1;
                    }
                }
                // Loop; proceed() will request the messages we just queued.
            }
        }
    }
}
```

- [ ] **Step 1: Write the failing test** — a driver-only test is impractical without a real protocol, so Task 3's proof is a compile + a smoke test using a trivial hand-rolled `StateMachine`. Add in `driver.rs` `#[cfg(test)]` a minimal 2-party `StateMachine` that broadcasts one message and outputs the concatenation of what it receives, driven over `in_memory_mesh(2)` + trivial codecs, asserting both parties output each other's message. (This isolates the driver's round/exchange logic from cggmp21 timing.)

```rust
// A trivial StateMachine: round 0 broadcast `mine`, then need one msg per peer,
// output = sorted collected payloads. Enough to exercise proceed/SendMsg/
// NeedsOneMoreMessage/received_msg/Output transitions and one exchange round.
```
(Write this test SM concretely: a struct with a small step counter, `proceed` returns `SendMsg(Outgoing::broadcast(mine))` on first call, then `NeedsOneMoreMessage` until it has collected n-1 messages via `received_msg`, then `Output`. Serialize `Msg = u8`.)

- [ ] **Step 2: Run to verify fail** → compile error (`drive_over_exchange` not found).
- [ ] **Step 3: Implement `driver.rs`** as above; add `mod driver; pub use driver::drive_over_exchange;` to `mod.rs`.
- [ ] **Step 4: Run to verify pass** — `cargo test -q -p fedimint-threshold-ecdsa driver:: -- --nocapture` → PASS.
- [ ] **Step 5: Format, lint, commit**

```bash
git commit -m "feat(threshold-ecdsa): drive cggmp21 state machines over exchange rounds"
```

---

### Task 4: Acceptance — DKG + threshold signing over the transport

**Files:**
- Modify: `crypto/threshold-ecdsa/src/tests.rs`
- Modify: `Cargo.toml` (add `state-machine` feature to workspace `cggmp21`)

**Interface consumed:** everything above + Phase 1's `run_keygen`/`assemble_key_share`/`group_public_key`/`Curve`.

This is the phase's ★ acceptance: real 4-party CGGMP21 keygen and 3-of-4 signing run entirely over `drive_over_exchange` + `InMemoryMesh` + `EncryptedRoundCodec`, with the resulting signature verified against the group key by the independent `secp256k1` crate — proving semantic equivalence with Phase 1's native async transport.

- [ ] **Step 1: Add the `state-machine` feature** to the root `Cargo.toml` `cggmp21` entry (now `features = ["hd-wallet", "hd-slip10", "curve-secp256k1", "state-machine"]`). Run `cargo check -q -p fedimint-threshold-ecdsa`.

- [ ] **Step 2: Write the failing test** (`tests.rs`)

```rust
#[tokio::test(flavor = "multi_thread")]
async fn keygen_and_signing_over_exchange_transport() {
    use crate::transport::{drive_over_exchange, in_memory_mesh, EncryptedRoundCodec};
    let secp = secp256k1::Secp256k1::new();

    // Per-party static encryption keypairs for the codec.
    let enc_sks: Vec<secp256k1::SecretKey> = (0..N).map(|i| {
        let mut b = [2u8; 32]; b[31] = (i + 1) as u8;
        secp256k1::SecretKey::from_slice(&b).expect("key")
    }).collect();
    let enc_pks: Vec<secp256k1::PublicKey> = enc_sks.iter().map(|sk| sk.public_key(&secp)).collect();

    // --- DKG over the transport ---
    let eid = cggmp21::ExecutionId::new(b"exchange-transport-keygen");
    let mut meshes = in_memory_mesh(N);
    let mut handles = Vec::new();
    for i in 0..N {
        let mut mesh = meshes.remove(0); // careful: index shifts — collect first instead
        let codec = EncryptedRoundCodec::new(i, enc_sks[i as usize], enc_pks.clone());
        handles.push(tokio::spawn(async move {
            let mut rng = rand::rngs::OsRng;
            let sm = cggmp21::keygen::<crate::Curve>(eid, i, N)
                .set_threshold(T).hd_wallet(true).into_state_machine(&mut rng);
            drive_over_exchange(sm, &codec, &mut mesh).await
                .expect("driver").expect("keygen")
        }));
    }
    // (Fix mesh ownership: build meshes into an owned Vec and `into_iter().enumerate()`
    //  so each task owns exactly its endpoint; don't use remove(0) with a shifting index.)
    let core_shares: Vec<_> = futures::future::join_all(handles).await
        .into_iter().map(|r| r.expect("join")).collect();
    let group_pk_curve = core_shares[0].shared_public_key();
    for s in &core_shares[1..] { assert_eq!(s.shared_public_key(), group_pk_curve); }

    // For signing we need full KeyShares (core + aux). Aux over the transport too,
    // OR reuse dealer aux for speed — but to prove signing over transport we run one
    // signing session over the mesh using shares assembled from transport-DKG cores +
    // per-party aux. Keep aux via run_aux_gen over the transport if time allows; if the
    // 4x-Paillier cost is prohibitive in one test, assemble shares from a trusted dealer
    // that reuses the SAME core public key is NOT possible — so run aux over transport.

    // --- signing 3-of-4 over the transport ---
    // Build full shares (assemble_key_share(core_i, aux_i)); pick signers [0,1,3];
    // each drives cggmp21::signing(eid_sign, pos, &signers, &share).sign_sync(rng, data)
    // via into a StateMachine over its mesh endpoint; digest = Keccak256(b"...").
    // Verify the returned secp256k1 signature against group_public_key(&shares[0]).
}
```
(The implementer must resolve two real concerns flagged inline: (a) mesh endpoint ownership — collect endpoints into an owned Vec and give each task its own by index, never `remove(0)` with a moving index; (b) signing needs full `KeyShare`s, so aux-info must also run — do it over the transport with `into_state_machine`, using a **fresh mesh per protocol invocation** since each `exchange` round consumes the mesh in lockstep. Signing uses `sign_sync(&mut rng, data)`. Use `cggmp21::signing::msg::Msg` message type. `data` via `DataToSign::from_scalar(Scalar::from_be_bytes_mod_order(digest))` as in Phase 1's `run_signing`.)

- [ ] **Step 3: Run to verify fail** → compile/red.
- [ ] **Step 4: Implement the test fully** (resolve ownership + aux-over-transport + signing). Add `futures = { workspace = true }` to dev-deps if needed for `join_all` (or use a `Vec` of `JoinHandle` and await in a loop).
- [ ] **Step 5: Run to verify pass**

Run: `cargo test --release -p fedimint-threshold-ecdsa keygen_and_signing_over_exchange -- --nocapture`
Expected: PASS. Runtime: minutes (4× keygen + 4× aux Paillier + one signing session). Report the runtime.

- [ ] **Step 6: Add a transport abort test**

A corrupted round payload must abort the driver cleanly (no panic, no hang). Add a wrapper `RoundExchange` that flips a byte in one party's returned payload on a chosen round, and assert `drive_over_exchange` returns `Err`. (Wrap `InMemoryMesh`; only corrupt the slot of one specific sender so the codec's AEAD/deserialize rejects it.)

- [ ] **Step 7: Format, lint, commit**

```bash
cargo clippy -q --locked --offline -p fedimint-threshold-ecdsa --all-targets -- -D warnings
git commit -m "test(threshold-ecdsa): DKG and signing over exchange transport"
```

---

### Task 5: Transport module docs + wrap-up

**Files:** `crypto/threshold-ecdsa/src/transport/mod.rs` (module docs), `src/lib.rs` (re-export surface)

- [ ] **Step 1: Module rustdoc** on `transport/mod.rs` documenting: the synchronous-all-to-all-round model, that broadcast messages are sent in clear and only point-to-point messages are encrypted (per-recipient ECDH+HKDF+AEAD), the `PartyIndex` (not `PeerId`) contract, and that production `RoundExchange` impls (config-gen `PeerHandleOps`, runtime consensus items) live in the consuming module crate — this crate ships only the in-memory mesh for tests. Note the driver's round-boundary rule (buffer outgoing until input is needed with an empty queue).

- [ ] **Step 2: Re-export surface** — in `lib.rs`, ensure `pub use transport::{drive_over_exchange, EncryptedRoundCodec, RoundExchange, PartyIndex};` (in_memory_mesh/InMemoryMesh stay test-facing: `#[cfg(test)]` or `pub` under a `test-util` feature — prefer keeping them `pub` in `transport` but documented as test utilities; do NOT gate behind cfg(test) since integration by later phases may want the mesh for their own tests — expose via a `test-util` feature if you want to keep it out of normal builds. Decide and document.)

- [ ] **Step 3: Full suite + docs**

Run: `cargo test --release -p fedimint-threshold-ecdsa` (all Phase 1 + Phase 2 tests) → all PASS.
Run: `cargo doc -q -p fedimint-threshold-ecdsa --no-deps` → no warnings.

- [ ] **Step 4: Format, lint, commit**

```bash
just format
cargo clippy -q --locked --offline -p fedimint-threshold-ecdsa --all-targets -- -D warnings
git commit -m "docs(threshold-ecdsa): transport module documentation"
```

---

## Self-review checklist (controller runs before dispatching Task 1)

- Spec coverage: interface A from the master plan (`RoundExchange`, `EncryptedRoundCodec`, `drive_over_exchange`) — all present (Tasks 1–3); acceptance proves equivalence (Task 4). ✓
- The `PeerHandleOps`/consensus adapters are correctly deferred to Phase 3/6 per the recorded master-plan deviation. ✓
- No `fedimint-core` dependency introduced (only `fedimint-hkdf`, `fedimint-aead`). ✓
- Open decision for the implementer, flagged in Task 5: whether `in_memory_mesh` is `pub` or behind a `test-util` feature — default to `pub` in the `transport` module, documented as a test utility, since later phases' tests will reuse it.
