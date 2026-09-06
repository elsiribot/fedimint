# InputAuth / Witness Core Patch — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a fedimint module verify its own input authorization against an opaque per-input witness, instead of core assuming every input is one key producing one schnorr signature over the txid.

**Architecture:** `InputMeta` gains an `auth` field saying either "core, check this key" (current behaviour, all seven modules) or "I already checked it". A new `TransactionSignature::Witnessed` variant carries one opaque witness per input; because `TransactionSignature` is excluded from `tx_hash_from_parts`, a self-verified module's signatures live outside the txid, so a signer set need not be fixed before signing. `verify_input` — already the stateless, rayon-parallel, pre-database hook — gains a context exposing a `Message` derived from the txid plus that input's witness.

**Tech Stack:** Rust 2024, `fedimint-core` / `fedimint-server-core` / `fedimint-server` / `fedimint-client-module`, `secp256k1` schnorr, `rayon`, `cargo test`.

**Spec:** `/home/user/projects/experimint/docs/superpowers/specs/2026-09-05-multispend-module-design.md`, section 2.

**Repo:** `/home/user/projects/fedimint-witness`, branch `experimint-v0.11-input-auth`, branched from `a50619eafc6` (the commit experimint currently pins).

## Global Constraints

- **No txid may change, for any transaction.** `Transaction::tx_hash_from_parts` hashes inputs, outputs and nonce, and must not be touched. Every task that changes `TransactionSignature` must leave that function alone.
- **`TransactionSignature::NaiveMultisig` must keep working.** A transaction whose inputs are all `InputAuth::Key` must remain valid in its existing encoding. This is what keeps the whole existing test suite meaningful as a regression check.
- **New enum variants go before `#[encodable_default] Default { variant, bytes }`,** never after, and never renumber existing variants.
- **`n <= 210`** is the DoS bound on self-verified signature counts. Core does not enforce it; consumers do. Do not add a core-side cap in this plan.
- **This repo has no Rust toolchain outside its nix devshell.** Every command must be wrapped: `nix develop -c cargo ...`. A bare `cargo` will fail with "command not found".
- **The verification gate**, run at the end of every task, must be green before the task is done:

  ```bash
  nix develop -c cargo check --workspace --all-targets
  nix develop -c cargo clippy --workspace --all-targets -- -D warnings
  nix develop -c cargo test -p fedimint-core
  nix develop -c cargo test -p fedimint-server
  nix develop -c cargo test -p fedimint-server-tests
  nix develop -c cargo test -p fedimint-mint-tests
  ```

  The compile gate is what catches the nine `InputMeta` sites and the eighteen `ClientInput` sites.

  `fedimint-mint-tests` is the load-bearing one. It is the cheapest crate in the tree that actually drives real transactions through `process_transaction_with_dbtx` — about 60s, no external daemons — and **nothing else in the workspace calls that function at all**. `fedimint-server`'s own tests are `FundingVerifier` arithmetic; `fedimint-server-tests` is migration-only. Without it, this branch's central claim — that the existing single-key path is unchanged — is verified by nothing that runs. The Task 4 review caught this; it is not optional.

  The remaining heavy suites (devimint, wasm-tests, lnv2-tests) need bitcoind/lnd/electrs and are left to CI. Baseline at `a50619eafc6` is clean, and `fedimint-mint-tests` was 21 passed / 1 ignored at the Task 4 head.
- Commit at the end of every task. Do not squash tasks together.

---

### Task 1: Witness carriage in `fedimint-core::transaction`

Purely additive. Nothing changes behaviour yet; this lands the new encoding and the helpers that later tasks consume.

**Files:**
- Modify: `fedimint-core/src/transaction.rs` (`TransactionSignature` at :131, `Transaction` impl block, `Debug` impl at :140)
- Modify: `fedimint-server-ui/src/dashboard/consensus_explorer.rs:229` (exhaustive match over `TransactionSignature`)
- Test: `fedimint-core/src/transaction.rs` (new `#[cfg(test)] mod tests` at the end of the file)

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `TransactionSignature::Witnessed(Vec<Vec<u8>>)`
  - `Transaction::input_witnesses(&self) -> Result<Vec<&[u8]>, TransactionError>`
  - `Transaction::verify_key_witness(witness: &[u8], msg: &secp256k1::Message, pk: &secp256k1::PublicKey) -> Result<(), TransactionError>` (associated function, no `self`)

- [ ] **Step 1: Write the failing tests**

Append to `fedimint-core/src/transaction.rs`:

```rust
#[cfg(test)]
mod tests {
    use fedimint_core::secp256k1::rand::rngs::OsRng;
    use secp256k1::{Keypair, Message, Secp256k1};

    use super::*;

    fn dummy_msg() -> Message {
        Message::from_digest([7u8; 32])
    }

    #[test]
    fn key_witness_roundtrips() {
        let secp = Secp256k1::new();
        let kp = Keypair::new(&secp, &mut OsRng);
        let sig = secp.sign_schnorr(&dummy_msg(), &kp);

        Transaction::verify_key_witness(sig.as_ref(), &dummy_msg(), &kp.public_key())
            .expect("a fresh signature over this message must verify");
    }

    #[test]
    fn key_witness_rejects_wrong_message() {
        let secp = Secp256k1::new();
        let kp = Keypair::new(&secp, &mut OsRng);
        let sig = secp.sign_schnorr(&dummy_msg(), &kp);

        let other = Message::from_digest([9u8; 32]);
        assert!(matches!(
            Transaction::verify_key_witness(sig.as_ref(), &other, &kp.public_key()),
            Err(TransactionError::InvalidSignature { .. })
        ));
    }

    #[test]
    fn key_witness_rejects_wrong_length() {
        let secp = Secp256k1::new();
        let kp = Keypair::new(&secp, &mut OsRng);

        assert!(matches!(
            Transaction::verify_key_witness(&[0u8; 63], &dummy_msg(), &kp.public_key()),
            Err(TransactionError::InvalidWitnessLength)
        ));
    }
}
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cd /home/user/projects/fedimint-witness && nix develop -c cargo test -p fedimint-core transaction::tests -- --nocapture`

Expected: FAIL to compile, `no function or associated item named 'verify_key_witness' found`.

- [ ] **Step 3: Add the variant and the helpers**

In `fedimint-core/src/transaction.rs`, extend the enum — the new variant goes **before** `Default`:

```rust
pub enum TransactionSignature {
    NaiveMultisig(Vec<fedimint_core::secp256k1::schnorr::Signature>),
    /// One opaque witness per input, positionally aligned with
    /// [`Transaction::inputs`].
    ///
    /// For an input whose module returns `InputAuth::Key`, the witness is
    /// exactly the 64 bytes of its schnorr signature over the txid. For an
    /// input whose module returns `InputAuth::SelfVerified`, the bytes mean
    /// whatever that module decides they mean.
    Witnessed(Vec<Vec<u8>>),
    #[encodable_default]
    Default {
        variant: u64,
        bytes: Vec<u8>,
    },
}
```

Add the `Debug` arm alongside the existing `NaiveMultisig` arm:

```rust
Self::Witnessed(witnesses) => {
    f.debug_struct("Witnessed")
        .field("len", &witnesses.len())
        .finish()
}
```

Add both helpers to `impl Transaction`:

```rust
/// One witness per input, whichever encoding this transaction uses.
///
/// Errors if the count does not match the input count, which is the check
/// [`Self::validate_signatures`] used to perform against the collected
/// public keys.
pub fn input_witnesses(&self) -> Result<Vec<&[u8]>, TransactionError> {
    match &self.signatures {
        TransactionSignature::NaiveMultisig(sigs) => {
            if sigs.len() != self.inputs.len() {
                return Err(TransactionError::InvalidWitnessLength);
            }
            Ok(sigs.iter().map(|sig| sig.as_ref() as &[u8]).collect())
        }
        TransactionSignature::Witnessed(witnesses) => {
            if witnesses.len() != self.inputs.len() {
                return Err(TransactionError::InvalidWitnessLength);
            }
            Ok(witnesses.iter().map(Vec::as_slice).collect())
        }
        TransactionSignature::Default { variant, .. } => {
            Err(TransactionError::UnsupportedSignatureScheme { variant: *variant })
        }
    }
}

/// Verify a witness belonging to an `InputAuth::Key` input: exactly one
/// 64-byte schnorr signature over the txid.
pub fn verify_key_witness(
    witness: &[u8],
    msg: &secp256k1::Message,
    pub_key: &secp256k1::PublicKey,
) -> Result<(), TransactionError> {
    let sig = secp256k1::schnorr::Signature::from_slice(witness)
        .map_err(|_| TransactionError::InvalidWitnessLength)?;

    secp256k1::global::SECP256K1
        .verify_schnorr(&sig, msg, &pub_key.x_only_public_key().0)
        .map_err(|_| TransactionError::InvalidSignature {
            tx: String::new(),
            hash: msg.as_ref().to_lower_hex_string(),
            sig: sig.consensus_encode_to_hex(),
            key: pub_key.consensus_encode_to_hex(),
        })
}
```

`to_lower_hex_string` comes from `bitcoin::hex::DisplayHex`, already imported at
the top of this file as `use bitcoin::hex::DisplayHex as _;`. Do not reach for
`consensus_encode_to_hex` on the message — `secp256k1::Message` is not
`Encodable`, only `AsRef<[u8]>`.

Note `InvalidSignature.tx` is left empty: this associated function has no access to the transaction. The caller in Task 4 has it and fills it in. Do not change the error variant's shape — the comment on `UnbalancedTransaction` explains that these types cannot change.

- [ ] **Step 4: Add the missing match arm in the dashboard**

`fedimint-server-ui/src/dashboard/consensus_explorer.rs:229` matches `TransactionSignature` exhaustively and will now fail to compile. Add, alongside the `NaiveMultisig` arm and mirroring its structure:

```rust
TransactionSignature::Witnessed(witnesses) => {
    div { "Type: Witnessed" }
    div { (format!("Witnesses: {}", witnesses.len())) }
}
```

Read the existing `NaiveMultisig` arm first and match its markup style exactly; it renders a signature count the same way.

- [ ] **Step 5: Run the tests to verify they pass**

Run: `nix develop -c cargo test -p fedimint-core transaction::tests`

Expected: PASS, 3 tests.

- [ ] **Step 6: Verify the workspace still builds**

Run: `nix develop -c cargo check --workspace --all-targets`

Expected: no errors.

- [ ] **Step 7: Commit**

```bash
cd /home/user/projects/fedimint-witness
git add fedimint-core/src/transaction.rs fedimint-server-ui/src/dashboard/consensus_explorer.rs
git commit -m "feat(core): carry one opaque witness per transaction input

Adds TransactionSignature::Witnessed alongside NaiveMultisig, plus
input_witnesses() to read either encoding uniformly and verify_key_witness()
for the one-key case. tx_hash_from_parts is untouched, so witnesses stay
outside the txid exactly as signatures already are.

Nothing consumes this yet."
```

---

### Task 2: `InputAuth` on `InputMeta`

Migrates every producer and the single consumer. Behaviour is deliberately unchanged: everything still returns `Key`, and core still verifies exactly as before.

**Files:**
- Modify: `fedimint-core/src/module/mod.rs:56` (`InputMeta`)
- Modify: `fedimint-server/src/consensus/transaction.rs:79` (the one consumer)
- Modify (one line each): `modules/fedimint-mint-server/src/lib.rs:617`, `modules/fedimint-mintv2-server/src/lib.rs:482`, `modules/fedimint-wallet-server/src/lib.rs:831`, `modules/fedimint-walletv2-server/src/lib.rs:655`, `modules/fedimint-ln-server/src/lib.rs:612`, `modules/fedimint-lnv2-server/src/lib.rs:539`, `modules/fedimint-dummy-server/src/lib.rs:219`
- Modify: `modules/fedimint-ln-server/src/lib.rs:1504` and `:1575` (two test fixtures constructing `InputMeta`)

**Interfaces:**
- Consumes: nothing from Task 1.
- Produces: `InputAuth::{Key(secp256k1::PublicKey), SelfVerified}`, and `InputMeta { amount: TransactionItemAmounts, auth: InputAuth }`.

- [ ] **Step 1: Write the failing test**

Append to the `mod tests` created in Task 1, in `fedimint-core/src/transaction.rs`:

```rust
#[test]
fn input_auth_key_carries_its_key() {
    use fedimint_core::module::InputAuth;

    let secp = Secp256k1::new();
    let kp = Keypair::new(&secp, &mut OsRng);

    let auth = InputAuth::Key(kp.public_key());
    match auth {
        InputAuth::Key(pk) => assert_eq!(pk, kp.public_key()),
        InputAuth::SelfVerified => panic!("expected Key"),
    }
}
```

- [ ] **Step 2: Run it to verify it fails**

Run: `nix develop -c cargo test -p fedimint-core transaction::tests::input_auth_key_carries_its_key`

Expected: FAIL to compile, `unresolved import fedimint_core::module::InputAuth`.

- [ ] **Step 3: Add the type and change `InputMeta`**

In `fedimint-core/src/module/mod.rs`, replacing the existing `InputMeta`:

```rust
/// How an input proves it is allowed to be spent.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum InputAuth {
    /// Core verifies a schnorr signature over the txid against this key,
    /// taking the signature from this input's witness.
    ///
    /// This is what every module did implicitly before witnesses existed.
    Key(secp256k1::PublicKey),
    /// The module already verified authorization in `verify_input`.
    ///
    /// A module returning this **must** have bound its check to
    /// `InputAuthCtx::txid_message()`. Verifying against anything else lets
    /// an attacker detach this input and reattach it to a transaction with
    /// different outputs.
    SelfVerified,
}

#[derive(Debug, PartialEq, Eq)]
pub struct InputMeta {
    pub amount: TransactionItemAmounts,
    pub auth: InputAuth,
}
```

`InputMeta`'s existing `#[derive(Debug, PartialEq, Eq)]` must be preserved
exactly — `modules/fedimint-ln-server/src/lib.rs:1513` does
`assert_eq!(processed_input_meta, expected_input_meta)`. That is also why
`InputAuth` derives `PartialEq` and `Eq` above.

- [ ] **Step 4: Update all seven producers plus the two `ln` test fixtures**

`InputAuth` joins the existing `fedimint_core::module::{...}` import in each
file. Every substitution, verbatim — note that three sites use field shorthand
for a local also named `pub_key`:

| File | Line | From | To |
| --- | --- | --- | --- |
| `modules/fedimint-mint-server/src/lib.rs` | 622 | `pub_key: *input.note.spend_key(),` | `auth: InputAuth::Key(*input.note.spend_key()),` |
| `modules/fedimint-mintv2-server/src/lib.rs` | 487 | `pub_key: input.note.nonce,` | `auth: InputAuth::Key(input.note.nonce),` |
| `modules/fedimint-wallet-server/src/lib.rs` | 836 | `pub_key,` | `auth: InputAuth::Key(pub_key),` |
| `modules/fedimint-walletv2-server/src/lib.rs` | 660 | `pub_key: input.tweak,` | `auth: InputAuth::Key(input.tweak),` |
| `modules/fedimint-ln-server/src/lib.rs` | 618 | `pub_key,` | `auth: InputAuth::Key(pub_key),` |
| `modules/fedimint-lnv2-server/src/lib.rs` | 544 | `pub_key,` | `auth: InputAuth::Key(pub_key),` |
| `modules/fedimint-dummy-server/src/lib.rs` | 229 | `pub_key: input.pub_key,` | `auth: InputAuth::Key(input.pub_key),` |

Plus the two `ln` test fixtures. At `modules/fedimint-ln-server/src/lib.rs:1509`
the expression spans three lines:

```rust
            auth: InputAuth::Key(
                preimage
                    .to_public_key()
                    .expect("should create Schnorr pubkey from preimage"),
            ),
```

and at `:1580`, `pub_key: gateway_key,` becomes
`auth: InputAuth::Key(gateway_key),`.

Confirm none were missed — this must print nothing when you are done:

```bash
grep -rn "InputMeta {" -A 14 --include=*.rs modules/ fedimint-core/ | grep "pub_key"
```

- [ ] **Step 5: Update the single consumer**

`fedimint-server/src/consensus/transaction.rs`, replacing `public_keys.push(meta.pub_key);`:

```rust
match meta.auth {
    InputAuth::Key(pub_key) => public_keys.push(pub_key),
    // No module returns this yet; Task 4 wires it up.
    InputAuth::SelfVerified => {}
}
```

Leave `transaction.validate_signatures(&public_keys)?;` exactly as it is. Behaviour is unchanged at this task.

- [ ] **Step 6: Run the full suite**

Run the gate:

```bash
nix develop -c cargo check --workspace --all-targets
nix develop -c cargo clippy --workspace --all-targets -- -D warnings
nix develop -c cargo test -p fedimint-core
nix develop -c cargo test -p fedimint-server
nix develop -c cargo test -p fedimint-server-tests
nix develop -c cargo test -p fedimint-mint-tests
```

Expected: PASS. Every existing test is now a regression check that the `Key` path is untouched.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "refactor(core): let inputs declare how they are authorized

InputMeta.pub_key becomes InputMeta.auth: InputAuth, whose Key variant is
exactly the previous behaviour. All seven modules return Key and core still
verifies through validate_signatures, so nothing changes yet.

The SelfVerified variant is unreachable until core threads witnesses through."
```

---

### Task 3: `InputAuthCtx` into `verify_input`

**Files:**
- Modify: `fedimint-core/src/module/mod.rs` (add `InputAuthCtx` next to `InputAuth`)
- Modify: `fedimint-server-core/src/lib.rs:93` (`ServerModule::verify_input`), `:230` (`IServerModule::verify_input`), `:363` (the blanket impl)
- Modify: `modules/fedimint-mint-server/src/lib.rs:564` (the only existing implementor)
- Modify: `fedimint-server/src/consensus/transaction.rs` (the rayon pass)
- Test: `fedimint-core/src/transaction.rs` `mod tests`

**Interfaces:**
- Consumes: `Transaction::input_witnesses` (Task 1), `InputAuth` (Task 2).
- Produces: `InputAuthCtx<'a>` with `new(TransactionId, u64, &'a [u8])`, `txid_message() -> secp256k1::Message`, `witness() -> &'a [u8]`, `in_idx() -> u64`, `verify_schnorr(&PublicKey, &schnorr::Signature) -> bool`.

- [ ] **Step 1: Write the failing tests**

Append to `mod tests` in `fedimint-core/src/transaction.rs`:

```rust
#[test]
fn auth_ctx_message_is_derived_from_the_txid() {
    use fedimint_core::module::InputAuthCtx;

    let txid = TransactionId::from_byte_array([3u8; 32]);
    let ctx = InputAuthCtx::new(txid, 0, &[]);

    assert_eq!(ctx.txid_message(), Message::from_digest([3u8; 32]));
    assert_eq!(ctx.in_idx(), 0);
    assert!(ctx.witness().is_empty());
}

#[test]
fn auth_ctx_verify_schnorr_binds_to_the_txid() {
    use fedimint_core::module::InputAuthCtx;

    let secp = Secp256k1::new();
    let kp = Keypair::new(&secp, &mut OsRng);

    let txid = TransactionId::from_byte_array([3u8; 32]);
    let other = TransactionId::from_byte_array([4u8; 32]);

    let ctx = InputAuthCtx::new(txid, 0, &[]);
    let sig = secp.sign_schnorr(&ctx.txid_message(), &kp);

    assert!(ctx.verify_schnorr(&kp.public_key(), &sig));

    let wrong = InputAuthCtx::new(other, 0, &[]);
    assert!(
        !wrong.verify_schnorr(&kp.public_key(), &sig),
        "a signature over a different txid must not verify"
    );
}
```

`TransactionId::from_byte_array` comes from `bitcoin::hashes::Hash`, which `transaction.rs` already imports as `use bitcoin::hashes::Hash;`.

- [ ] **Step 2: Run them to verify they fail**

Run: `nix develop -c cargo test -p fedimint-core transaction::tests`

Expected: FAIL to compile, `unresolved import fedimint_core::module::InputAuthCtx`.

- [ ] **Step 3: Add `InputAuthCtx`**

In `fedimint-core/src/module/mod.rs`, directly after `InputAuth`:

```rust
/// What a module needs to verify its own input authorization.
///
/// Deliberately exposes no raw txid bytes. The only message reachable from
/// here is the one an input must bind to, so the ergonomic thing to write is
/// also the correct thing to write.
pub struct InputAuthCtx<'a> {
    txid: TransactionId,
    in_idx: u64,
    witness: &'a [u8],
}

impl<'a> InputAuthCtx<'a> {
    pub fn new(txid: TransactionId, in_idx: u64, witness: &'a [u8]) -> Self {
        Self { txid, in_idx, witness }
    }

    /// The message every self-verified input must bind its signatures to.
    pub fn txid_message(&self) -> secp256k1::Message {
        secp256k1::Message::from_digest(*self.txid.as_ref())
    }

    /// This input's witness, meaning whatever the module decides.
    pub fn witness(&self) -> &'a [u8] {
        self.witness
    }

    pub fn in_idx(&self) -> u64 {
        self.in_idx
    }

    /// Prefer this over `txid_message`: it cannot be pointed at the wrong
    /// message.
    pub fn verify_schnorr(
        &self,
        pub_key: &secp256k1::PublicKey,
        sig: &secp256k1::schnorr::Signature,
    ) -> bool {
        secp256k1::global::SECP256K1
            .verify_schnorr(sig, &self.txid_message(), &pub_key.x_only_public_key().0)
            .is_ok()
    }
}
```

If `TransactionId` is not already in scope in `module/mod.rs`, import it with `use crate::TransactionId;`.

- [ ] **Step 4: Thread it through the trait, the dyn trait and the blanket impl**

`fedimint-server-core/src/lib.rs:93`:

```rust
fn verify_input(
    &self,
    _input: &<Self::Common as ModuleCommon>::Input,
    _ctx: &InputAuthCtx<'_>,
) -> Result<(), <Self::Common as ModuleCommon>::InputError> {
    Ok(())
}
```

`:230`:

```rust
fn verify_input(&self, input: &DynInput, ctx: &InputAuthCtx<'_>) -> Result<(), DynInputError>;
```

`:363`, keeping the existing downcast body and passing `ctx` through:

```rust
fn verify_input(&self, input: &DynInput, ctx: &InputAuthCtx<'_>) -> Result<(), DynInputError> {
    <Self as ServerModule>::verify_input(
        self,
        input
            .as_any()
            .downcast_ref::<<<Self as ServerModule>::Common as ModuleCommon>::Input>()
            .expect("incorrect input type passed to module plugin"),
        ctx,
    )
    .map_err(Into::into)
}
```

Match the existing body's error conversion exactly — read it before editing rather than trusting the `.map_err` shown here.

`modules/fedimint-mint-server/src/lib.rs:564` is the only existing implementor; add the parameter and ignore it:

```rust
fn verify_input(&self, input: &MintInput, _ctx: &InputAuthCtx<'_>) -> Result<(), MintInputError> {
```

- [ ] **Step 5: Update the call site**

In `fedimint-server/src/consensus/transaction.rs`, hoist the txid above the rayon pass and replace that pass. The current version clones every input to satisfy `into_par_iter`; indexing avoids the clone:

```rust
let txid = transaction.tx_hash();
let witnesses = transaction.input_witnesses()?;

// We can not return the error here as errors are not returned in a specified
// order and the client still expects consensus on the error. Since the
// error is not extensible at the moment we need to incorrectly return the
// InvalidWitnessLength variant.
(0..transaction.inputs.len())
    .into_par_iter()
    .try_for_each(|in_idx| {
        let input = &transaction.inputs[in_idx];
        let ctx = InputAuthCtx::new(txid, in_idx as u64, witnesses[in_idx]);

        modules
            .get_expect(input.module_instance_id())
            .verify_input(input, &ctx)
    })
    .map_err(|_| TransactionError::InvalidWitnessLength)?;
```

Delete the now-duplicate `let txid = transaction.tx_hash();` further down.

- [ ] **Step 6: Run the full suite**

Run the gate:

```bash
nix develop -c cargo check --workspace --all-targets
nix develop -c cargo clippy --workspace --all-targets -- -D warnings
nix develop -c cargo test -p fedimint-core
nix develop -c cargo test -p fedimint-server
nix develop -c cargo test -p fedimint-server-tests
nix develop -c cargo test -p fedimint-mint-tests
```

Expected: PASS. `input_witnesses()` now runs on every transaction, so a regression here means the length check disagrees with the old `pub_keys.len() != signatures.len()`.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "feat(server): give verify_input the txid and its input's witness

InputAuthCtx hands a module a Message derived from the txid rather than raw
bytes, so binding to the transaction is the path of least resistance. Also
drops the per-input clone the rayon pass needed.

No module self-verifies yet."
```

---

### Task 4: Core honours `SelfVerified`

**Files:**
- Modify: `fedimint-server/src/consensus/transaction.rs` (the input loop)
- Modify: `fedimint-core/src/transaction.rs` (remove `validate_signatures`)
- Modify: `fedimint-core/src/module/version.rs:93` (`CORE_CONSENSUS_VERSION`)

**Interfaces:**
- Consumes: `input_witnesses`, `verify_key_witness` (Task 1); `InputAuth` (Task 2); `InputAuthCtx` (Task 3).
- Produces: `CORE_CONSENSUS_VERSION = CoreConsensusVersion::new(2, 2)`.

- [ ] **Step 1: Replace the batched signature check with a per-input one**

In `fedimint-server/src/consensus/transaction.rs`, delete `let mut public_keys = Vec::new();` and the `transaction.validate_signatures(&public_keys)?;` line. Inside the input loop, after `funding_verifier.add_input(meta.amount)?;`:

```rust
match meta.auth {
    InputAuth::Key(pub_key) => {
        Transaction::verify_key_witness(witnesses[in_idx as usize], &msg, &pub_key).map_err(
            |err| match err {
                TransactionError::InvalidSignature { hash, sig, key, .. } => {
                    TransactionError::InvalidSignature {
                        tx: transaction.consensus_encode_to_hex(),
                        hash,
                        sig,
                        key,
                    }
                }
                other => other,
            },
        )?;
    }
    // Already verified in the rayon pass above, bound to `txid`.
    InputAuth::SelfVerified => {}
}
```

with `let msg = secp256k1::Message::from_digest(*txid.as_ref());` computed once beside `let witnesses = ...`.

Note the behavioural change worth understanding: signatures are now checked *during* the input loop rather than after it, so `process_input` has already written to `dbtx` for that input when a signature fails. This is equivalent, because any error aborts the whole database transaction — but it is the kind of thing a reviewer should be told rather than left to notice.

- [ ] **Step 2: Delete `validate_signatures`**

Remove the whole `pub fn validate_signatures` from `fedimint-core/src/transaction.rs`. Confirm nothing else calls it:

```bash
grep -rn "validate_signatures" --include=*.rs . | grep -v "^./target"
```

Expected: no output.

- [ ] **Step 3: Bump the core consensus version**

`fedimint-core/src/module/version.rs:93`:

```rust
pub const CORE_CONSENSUS_VERSION: CoreConsensusVersion = CoreConsensusVersion::new(2, 2);
```

This changes which transactions are valid even though it changes no encoding, which is exactly what a consensus version exists to signal.

- [ ] **Step 4: Run the full suite**

Run the gate:

```bash
nix develop -c cargo check --workspace --all-targets
nix develop -c cargo clippy --workspace --all-targets -- -D warnings
nix develop -c cargo test -p fedimint-core
nix develop -c cargo test -p fedimint-server
nix develop -c cargo test -p fedimint-server-tests
nix develop -c cargo test -p fedimint-mint-tests
```

Expected: PASS. This is the load-bearing regression check for the whole plan: every existing transaction test now flows through `input_witnesses` and `verify_key_witness` instead of `validate_signatures`.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(server): verify input authorization per input

Core now checks each input's witness against the key its module named, or
skips the check entirely when the module reports SelfVerified. Replaces the
batched validate_signatures, which could only express one key per input.

Bumps CORE_CONSENSUS_VERSION to 2.2: no encoding changes, but which
transactions are valid does."
```

---

### Task 5: Integration coverage through `process_transaction_with_dbtx`

Proves both encodings survive a real trip through consensus. The `SelfVerified` path gets its first real consumer, and its end-to-end test, in the multispend module plan — building a throwaway self-verifying module here would cost ~200 lines of `ServerModule` boilerplate to test plumbing that plan 2 exercises for real. That is a deliberate gap, recorded here so it is not mistaken for an oversight.

**Files:**
- Create: `fedimint-server-tests/tests/transaction_auth.rs`
- Modify: `fedimint-server-tests/Cargo.toml` (add a `[[test]]` entry)

**Interfaces:**
- Consumes: everything from Tasks 1–4.
- Produces: nothing consumed later.

- [ ] **Step 1: Register the test target**

In `fedimint-server-tests/Cargo.toml`, after the existing `[[test]]` block:

```toml
[[test]]
name = "fedimint_server_transaction_auth"
path = "tests/transaction_auth.rs"
```

- [ ] **Step 2: Write the failing tests**

Create `fedimint-server-tests/tests/transaction_auth.rs`. The `Dummy` module is used because it accepts any input amount and any pubkey, so a transaction can be balanced trivially; `DummyConfig` is two unit structs.

```rust
use fedimint_core::core::{DynInput, DynOutput, ModuleInstanceId};
use fedimint_core::db::Database;
use fedimint_core::module::registry::ModuleRegistry;
use fedimint_core::module::{AmountUnit, CommonModuleInit, CoreConsensusVersion};
use fedimint_core::secp256k1::rand::rngs::OsRng;
use fedimint_core::secp256k1::{Keypair, Message, Secp256k1};
use fedimint_core::transaction::{Transaction, TransactionError, TransactionSignature};
use fedimint_core::Amount;
use fedimint_dummy_common::config::{DummyConfig, DummyConfigConsensus, DummyConfigPrivate};
use fedimint_dummy_common::{DummyCommonInit, DummyInput, DummyOutput};
use fedimint_dummy_server::Dummy;
use fedimint_server::consensus::transaction::{process_transaction_with_dbtx, TxProcessingMode};
use fedimint_server::core::{DynServerModule, ServerModuleRegistry};
use fedimint_testing_core::db::mem_database;

const INSTANCE: ModuleInstanceId = 0;
const VERSION: CoreConsensusVersion = CoreConsensusVersion::new(2, 2);

fn registry() -> ServerModuleRegistry {
    let dummy = Dummy::new(DummyConfig {
        private: DummyConfigPrivate,
        consensus: DummyConfigConsensus,
    });

    ModuleRegistry::from_iter([(
        INSTANCE,
        DummyCommonInit::KIND,
        DynServerModule::from(dummy),
    )])
}

/// A balanced one-in one-out dummy transaction, unsigned.
fn unsigned_tx(pub_key: fedimint_core::secp256k1::PublicKey) -> (Vec<DynInput>, Vec<DynOutput>, [u8; 8]) {
    let inputs = vec![DynInput::from_typed(
        INSTANCE,
        DummyInput {
            amount: Amount::from_msats(1000),
            unit: AmountUnit::BITCOIN,
            pub_key,
        },
    )];
    let outputs = vec![DynOutput::from_typed(
        INSTANCE,
        DummyOutput {
            amount: Amount::from_msats(1000),
            unit: AmountUnit::BITCOIN,
        },
    )];
    (inputs, outputs, [0x11; 8])
}

async fn process(tx: &Transaction) -> Result<(), TransactionError> {
    let db: Database = mem_database();
    let mut dbtx = db.begin_transaction().await;
    let res = process_transaction_with_dbtx(
        registry(),
        &mut dbtx.to_ref_nc(),
        tx,
        VERSION,
        TxProcessingMode::Consensus,
    )
    .await;
    res
}

fn sign(inputs: &[DynInput], outputs: &[DynOutput], nonce: [u8; 8], kp: &Keypair)
    -> fedimint_core::secp256k1::schnorr::Signature
{
    let txid = Transaction::tx_hash_from_parts(inputs, outputs, nonce);
    let msg = Message::from_digest(*txid.as_ref());
    Secp256k1::new().sign_schnorr(&msg, kp)
}

#[tokio::test]
async fn naive_multisig_encoding_still_accepted() {
    let kp = Keypair::new(&Secp256k1::new(), &mut OsRng);
    let (inputs, outputs, nonce) = unsigned_tx(kp.public_key());
    let sig = sign(&inputs, &outputs, nonce, &kp);

    let tx = Transaction {
        inputs,
        outputs,
        nonce,
        signatures: TransactionSignature::NaiveMultisig(vec![sig]),
    };

    process(&tx).await.expect("the legacy encoding must still work");
}

#[tokio::test]
async fn witnessed_encoding_accepted() {
    let kp = Keypair::new(&Secp256k1::new(), &mut OsRng);
    let (inputs, outputs, nonce) = unsigned_tx(kp.public_key());
    let sig = sign(&inputs, &outputs, nonce, &kp);

    let tx = Transaction {
        inputs,
        outputs,
        nonce,
        signatures: TransactionSignature::Witnessed(vec![sig.as_ref().to_vec()]),
    };

    process(&tx).await.expect("a Key input's witness is its signature");
}

#[tokio::test]
async fn witness_over_a_different_txid_rejected() {
    let kp = Keypair::new(&Secp256k1::new(), &mut OsRng);
    let (inputs, outputs, nonce) = unsigned_tx(kp.public_key());

    // Sign a transaction with a different nonce, hence a different txid.
    let sig = sign(&inputs, &outputs, [0x22; 8], &kp);

    let tx = Transaction {
        inputs,
        outputs,
        nonce,
        signatures: TransactionSignature::Witnessed(vec![sig.as_ref().to_vec()]),
    };

    assert!(matches!(
        process(&tx).await,
        Err(TransactionError::InvalidSignature { .. })
    ));
}

#[tokio::test]
async fn wrong_witness_count_rejected() {
    let kp = Keypair::new(&Secp256k1::new(), &mut OsRng);
    let (inputs, outputs, nonce) = unsigned_tx(kp.public_key());

    let tx = Transaction {
        inputs,
        outputs,
        nonce,
        signatures: TransactionSignature::Witnessed(vec![]),
    };

    assert!(matches!(
        process(&tx).await,
        Err(TransactionError::InvalidWitnessLength)
    ));
}
```

- [ ] **Step 3: Run them**

Run: `nix develop -c cargo test -p fedimint-server-tests --test fedimint_server_transaction_auth`

Expected: PASS, 4 tests. If imports do not resolve, fix them against the real paths — `fedimint-server-tests/tests/migration.rs` imports `Dummy`, `DummyInput`, `DummyOutput` and `Transaction` and is the reference for what is public. `mem_database` may be named differently in `fedimint-testing-core`; check with `grep -rn "fn mem_database\|pub fn.*Database" fedimint-testing-core/src/db.rs`.

- [ ] **Step 4: Commit**

```bash
git add fedimint-server-tests/
git commit -m "test(server): cover both witness encodings end to end

Runs a dummy transaction through process_transaction_with_dbtx under
NaiveMultisig and Witnessed, and checks that a witness signed over a
different txid and a wrong witness count are both rejected.

SelfVerified gets its first real consumer, and its end-to-end coverage, in
the multispend module."
```

---

### Task 6: Client can attach signatures it did not produce

Without this, no client can build a multi-party transaction: `ClientInput.keys: Vec<Keypair>` can only sign with keys held locally.

**Files:**
- Modify: `fedimint-client-module/src/transaction/builder.rs:29` (`ClientInput`), `:546` (signature assembly), `:130`, `:165`, `:218` (the three places `input.keys` is moved)
- Modify: every caller constructing `ClientInput { .. }` — find with the grep in Step 2

**Interfaces:**
- Consumes: `TransactionSignature::Witnessed` (Task 1).
- Produces: `ClientInputAuth::{Keys(Vec<Keypair>), Witness(Vec<u8>)}` and `ClientInput { input, auth, amounts }`.

- [ ] **Step 1: Add the auth enum**

In `fedimint-client-module/src/transaction/builder.rs`:

```rust
/// How a client authorizes an input it is contributing.
#[derive(Clone, Debug)]
pub enum ClientInputAuth {
    /// Sign the txid with each of these keys. One signature per keypair,
    /// flattened across inputs, exactly as before witnesses existed.
    Keys(Vec<Keypair>),
    /// Use these witness bytes verbatim. For inputs whose module verifies
    /// its own authorization, where the signatures may have been produced by
    /// other people entirely.
    Witness(Vec<u8>),
}

pub struct ClientInput<I = DynInput> {
    pub input: I,
    pub auth: ClientInputAuth,
    pub amounts: Amounts,
}
```

- [ ] **Step 2: Update every construction site**

```bash
grep -rn "ClientInput {" --include=*.rs . | grep -v "^./target"
grep -rn "keys: vec!\[" --include=*.rs . | grep -v "^./target"
```

Each `keys: <expr>` becomes `auth: ClientInputAuth::Keys(<expr>)`. The three internal moves at `builder.rs:130`, `:165` and `:218` become `auth: input.auth`.

- [ ] **Step 3: Emit witnesses**

Replace the assembly at `builder.rs:546`. Every input now contributes exactly one witness, so the flat `NaiveMultisig` vector is no longer expressible in general:

```rust
let witnesses: Vec<Vec<u8>> = input_auths
    .iter()
    .map(|auth| match auth {
        ClientInputAuth::Keys(keys) => {
            // A Key input's witness is its single signature. More than one
            // key per input can no longer be expressed, and never had a
            // server-side meaning: core returned one pub_key per input.
            assert_eq!(keys.len(), 1, "an input contributes exactly one witness");
            secp_ctx.sign_schnorr(&msg, &keys[0]).as_ref().to_vec()
        }
        ClientInputAuth::Witness(bytes) => bytes.clone(),
    })
    .collect();

let transaction = Transaction {
    inputs,
    outputs,
    nonce,
    signatures: TransactionSignature::Witnessed(witnesses),
};
```

with `input_keys` renamed to `input_auths` in the `multiunzip` above it, taking `input.auth.clone()`.

The assertion is the honest place to discover whether any existing module puts more than one keypair on a single input. If one does, that input was already being verified against a single `pub_key`, so the extra keys were dead weight — but find out rather than assume: run the full suite in Step 4 and read any panic carefully before changing the assertion into something quieter.

- [ ] **Step 4: Run the full suite**

Run the gate:

```bash
nix develop -c cargo check --workspace --all-targets
nix develop -c cargo clippy --workspace --all-targets -- -D warnings
nix develop -c cargo test -p fedimint-core
nix develop -c cargo test -p fedimint-server
nix develop -c cargo test -p fedimint-server-tests
nix develop -c cargo test -p fedimint-mint-tests
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat(client): let a client attach witnesses it did not sign

ClientInput.keys becomes ClientInputAuth, whose Witness arm carries bytes
produced elsewhere. Without it a client can only ever build transactions
authorized by keys it holds, which rules out every multi-party input.

The builder now emits TransactionSignature::Witnessed."
```

---

## What this plan does not do

- **No `SelfVerified` consumer.** Nothing in the fedimint tree returns it after this plan; the multispend module is the first. Task 5 explains the reasoning.
- **No witness size cap in core.** Listed as an open question in the spec; deferred until there is a real consumer to size it against.
- **No upstream issue filed.** The draft lives at `/tmp/claude-1000/-home-user-projects-experimint/60422aec-83d1-46ca-b80e-4a0321d8c590/scratchpad/fedimint-issue-input-auth.md` and its symbol names were verified against this fork, not against upstream master, which is a different API generation.
- **Witness malleability is unconfirmed.** The spec flags it: two submissions of one txid with different valid witnesses become possible, and the claim that consensus dedup makes this benign has not been checked against the submission path. Worth resolving before this leaves the branch.

---

## Deviations from this plan, as executed

Recorded after the fact so the plan and the branch agree.

- **Task 6: `ClientInputAuth::Keys` wraps one `Keypair`, not a `Vec`.** The plan
  mandated `Keys(Vec<Keypair>)` plus a runtime `assert_eq!(keys.len(), 1, ..)`
  in `build()`. The Task 6 review flagged that as a panic in library code with
  no error channel to route a module bug into, and the plan's justification for
  it rested on a survey of construction sites that turned out to be wrong —
  there are 27 sites, not 18, and two of them passed *zero* keys, so the
  assertion would in fact have fired. The human overruled the plan: the type now
  makes "exactly one key per input" a compile-time fact and the assertion is
  gone.
- **The gate gained `cargo clippy -- -D warnings`.** The repo's own `justfile`
  runs it, and the plan's gate did not, so a `clippy::clone_on_copy` error
  reached review unnoticed.
- **The gate gained `cargo test -p fedimint-mint-tests`.** See the Global
  Constraints note: nothing else in the workspace calls
  `process_transaction_with_dbtx`, so without it the branch's central claim was
  verified by nothing that runs.
- **Task 1 additionally added a `Witnessed` arm to `validate_signatures`.** Not
  in the plan, but forced: adding a third enum variant made the existing match
  non-exhaustive. Task 4 deleted `validate_signatures` entirely, retiring it.
