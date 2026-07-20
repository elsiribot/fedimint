## Motivation

Today setup generates AlephBFT signing material and all module configs before consensus starts. This couples module DKG to initial federation setup, prevents adding modules later, and requires guardians to back up all private module configuration.

We should split setup into two phases:

1. Bootstrap only the core federation/AlephBFT configuration.
2. Generate initial and future module configurations through a protocol coordinated by the running federation's consensus.

Goals:

- Add modules to a running federation without re-running setup.
- Guardian recovery from approximately: mnemonic + public bootstrap config (or invite) + the federation's signed consensus history.
- One protocol for day-0 and later module generation (setup becomes bootstrap-only).
- Existing federations gain seed recovery via a one-time genesis commit (see below).

This supersedes the earlier draft of this issue, which proposed transporting the full DKG transcript through consensus. After further analysis the direction is now: **consensus coordinates, direct P2P transports.** Rationale below.

## Design principles

1. **Consensus coordinates, P2P transports.** DKG packets flow over the running federation's existing authenticated peer connections. Consensus carries only proposal, approval, result, and activation items. Consequences:
   - No secret-share ciphertexts in permanent, publicly-served history (clients download signed session outcomes for recovery, so anything in history is effectively public — persisting encrypted shares there is a harvest-now-decrypt-later liability and makes the guardian mnemonic a retroactive-and-prospective single point of failure given only public data).
   - The existing `PeerHandle`/G1/G2 DKG code is reused nearly as-is instead of being extracted into pure replayable state machines.
   - No per-round consensus-ordering latency. This matters: the mint module runs one sequential G2 DKG per amount tier, and `PeerHandleOps` is sequential by construction.
   - Note this does not change liveness in practice: a DKG needs all n peers live eventually regardless of transport, and a stalled generation never blocks consensus — it is merely pending.
2. **Determinism first, encrypted backup otherwise.** All generation randomness (module-local keys, G1/G2 polynomial randomness) is derived from a domain-separated `ModuleConfigGenSecret(root, generation_id)`. Any fresh entropy that cannot be re-derived from the root MUST be committed to consensus as an encrypted backup before first use. Bootstrap-time secrets (which predate consensus) follow the same rule with the public bootstrap config as the commitment medium: derive from the root where possible, otherwise store encrypted in the bootstrap config.
3. **Abort-and-retry instead of transcript replay.** Generations are cheap (seconds). A crash or invalid message aborts the generation; retry allocates a fresh `generation_id`. Because polynomial randomness is derived from `(root, generation_id)`, generation IDs MUST be structurally single-use — replaying the same polynomial into a run where other peers change contributions is unsound. No complaint protocol in v1; the documented upgrade path is DLEQ-reveal (the recipient publishes the ephemeral ECDH shared point plus a DLEQ proof, letting everyone decrypt and verify the disputed ciphertext without exposing the recipient's long-term key).
4. **Unanimity.** Every guardian must approve the exact proposal (pinning module kind, `ModuleConsensusVersion`, and full `ConfigGenModuleArgs`) and participate in generation. n-of-n DKG participation forces this anyway, and it doubles as a "does every guardian run code supporting this module+version" check. One active generation at a time. Subset-participation DKG (modules keyed k-of-m for m < n) is explicitly out of scope: it changes the per-module trust model.

## Current architecture (obstacles)

- `ServerConfig::distributed_gen` runs all module DKGs over setup-only P2P connections, assigns `ModuleInstanceId`s positionally (`.filter(enabled).enumerate()` over registry order) and never persists a kind→id map.
- Config lives in `consensus.json`/`local.json`/`private.json`; the presence of `consensus.json` is the setup/consensus mode switch. There is no way to change module config atomically with consensus state.
- The running server assumes a static module set: decoders, `ModuleRegistry`, proposal tasks, module API routes, and the cached client config are created once at startup. `consensus/mod.rs` bails on config referencing an unknown module kind.
- The client already has additive-config groundwork: it refetches config on startup, `validate_config_update` enforces "modules can only be added", pending configs are promoted at next start, and unknown module kinds are skipped. Nothing changes server-side today, so this machinery is dormant — and it currently trusts whichever single guardian serves the config.

## Proposed architecture

### Bootstrap configuration

Initial setup agrees only on global state: guardian membership and identities, API/P2P endpoints, AlephBFT broadcast public keys, guardian recovery-encryption public keys, core consensus version, and global federation settings. The federation initially runs with no ordinary modules; the modules selected during setup are generated through the same runtime protocol as modules added later.

### Core consensus items

```rust
enum ConfigGenConsensusItem {
    Propose { proposal: ModuleConfigProposal },          // kind, consensus version, args, proposer
    Approve { generation_id: ModuleGenerationId },        // unanimous, exact proposal
    Result {
        generation_id: ModuleGenerationId,
        consensus_config: ServerModuleConsensusConfig,
        encrypted_private_config: EncryptedModuleConfig,  // under mnemonic-derived key
    },
    Ready { generation_id: ModuleGenerationId, config_hash: sha256::Hash, active_from_session: u64 },
    Abort { generation_id: ModuleGenerationId, reason: ConfigGenAbortReason },
}
```

Lifecycle: `Proposed -> Approved -> Running (off-consensus DKG) -> Generated -> Ready -> Active`, with `Abort` reachable until `Ready`. The generation state machine is persisted in the DB so restarts resume or abort deterministically.

### DKG transport

Once a generation is unanimously approved, each server starts a generation worker that speaks the existing `PeerHandleOps` protocol over the runtime P2P connections, namespaced by `generation_id`. Module `distributed_gen` implementations are unchanged apart from receiving the derived gen secret. Rule: module config generation may touch nothing but `PeerHandleOps` and the injected secret — environmental validation (bitcoind reachability, network params) happens at proposal/approval time, not during generation.

### Result commitment and activation

When generation completes, each guardian commits its `Result`. Activation (`Ready`) occurs only after all guardians agree on the consensus-config hash and report successful local decryption, validation, and module preparation, and schedules `active_from_session`. Module consensus items and transactions referencing the new instance are rejected deterministically before that session. Instance IDs come from a monotonic allocator in consensus state and are never reused.

**Activation is hot (no restart)**: the consensus engine initializes the module at the start of its activation session (migrations, module init, decoder extension, CI proposal submitter) and publishes the extended module set on a watch channel; an api refresher respawns the websocket api server and dashboard with the extended endpoint set and swaps the iroh api handlers in place. The startup path still initializes active modules from the generation log and serves as the crash/offline-guardian catch-up path — both paths share `DynModuleActivator` and must produce identical state. (Milestone 1 used a coordinated restart via the scheduled-shutdown-at-session mechanism; superseded.)

### Config storage and identity

- Module configs move from files to the DB, updated atomically with the consensus state that activated them. The bootstrap config stays as a write-once file. Existing federations run a one-time migration folding `consensus.json` modules into the DB as genesis generation results.
- The client config becomes a revision sequence `(revision, config_hash)`.
- **Client config updates must be consensus-attested.** With dynamic configs, a single malicious guardian could serve an "additive" update containing a fake module (e.g. a walletv2 instance with attacker-controlled descriptor keys, silently redirecting deposits). Clients accept a new revision only with a proof from a signed session outcome containing the corresponding `Ready` item, or at minimum an identical revision from a threshold of guardians.

### Genesis commit for existing federations

A one-time generation type in which each guardian commits its *existing* module private configs, encrypted under its mnemonic-derived key, as `Result` items — no DKG runs. This gives already-running federations the same seed-recovery guarantees as newly bootstrapped ones, which a bootstrap-only setup alone would never provide.

## Guardian recovery model

Each guardian has one BIP39 root with domain-separated children for: bootstrap/recovery encryption, per-generation randomness, and final module-config encryption. The public recovery key in the bootstrap config identifies the guardian's `PeerId`.

Recovery flow:

1. Derive the recovery identity from the mnemonic.
2. Download the public bootstrap config from any guardian; recover bootstrap signing/transport material (derived or decrypted per principle 2).
3. Fetch signed session outcomes from session zero and verify against the bootstrap broadcast keys.
4. Decrypt own encrypted module configs as `Result` items appear in history.
5. Install module decoders at their activation points and replay consensus to rebuild the server database.

Two explicit caveats:

- **Recovery reconstructs consensus-derived state only.** Some server DB state never passes through consensus and is not recoverable this way — notably client e-cash backups (stored directly from an API handler) and API announcements (signed gossip). These need an enumerated audit: each is either re-populated organically, replicated peer-to-peer after recovery, or accepted as lost-with-threshold-survival. This should be a table in the design, not an open question.
- **Full history retention becomes a protocol guarantee**, not an operational accident. Any future history-pruning/snapshot scheme must carry `Result` items (and activation metadata) forward.

## Security considerations

- **Mnemonic blast radius.** Mnemonic + public history yields all of that guardian's committed private module configs, and (via derived generation randomness) its contributions to future generations. This is the deliberate price of seed recovery. It is materially smaller than under the transcript-in-consensus design, since DKG shares never enter public history. `Result` blobs still carry harvest-now-decrypt-later risk (ECDH-based encryption in a permanent public log); acceptable for now, worth revisiting if post-quantum KEMs become practical here.
- **Config-update injection** — addressed by consensus attestation above; must be designed in from the start.
- **Deterministic-randomness reuse** — addressed by structurally single-use generation IDs.
- **Version skew.** Proposals pin `ModuleConsensusVersion`; peers whose registry lacks the kind or version reject at approval time, so unanimity guarantees code availability before any DKG starts. The new consensus items themselves require a `CoreConsensusVersion` bump, so all guardians upgrade before the first runtime generation.

## Open questions

- Bootstrap secret handling details: which bootstrap secrets are derivable from the root vs stored encrypted in the bootstrap config (per principle 2)?
- Long-running clients (gateways) currently promote pending configs only at restart — is restart-to-see-new-modules acceptable client-side for v1?
- Exact client attestation mechanism: signed-session proof vs threshold-of-guardians config agreement?
- The recoverability audit of non-consensus DB state (client backups, announcements): replicate, re-populate, or accept loss?
- UX for proposing modules: dashboard flow, and how `ConfigGenModuleArgs` are agreed before `Propose`.

## Implementation sequence

1. Move module configs into the DB with an explicit instance-ID allocator; one-time genesis migration from `consensus.json`.
2. Revisioned, consensus-attested client config; wire up the dormant client refresh path.
3. Core generation state machine (`Propose/Approve/Result/Ready/Abort`), persisted lifecycle, single active generation.
4. Runtime P2P DKG channel speaking `PeerHandleOps`, namespaced by generation ID; deterministic `ModuleConfigGenSecret` derivation (fixes wallet `OsRng` restart-sensitivity).
5. Guardian root derivation and encrypted `Result` payloads.
6. Coordinated-restart activation via scheduled shutdown.
7. Genesis commit for existing federations.
8. Bootstrap-only setup: day-0 modules generated through the runtime protocol.
9. Hot (no-restart) activation.
10. Client-side dynamic module initialization and the guardian recovery flow.
