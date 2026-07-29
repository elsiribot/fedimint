# USDT deposit-by-proof — design

**Status:** approved design (2026-07-29), pending implementation plan.

**Goal:** Eliminate the federation's per-deposit EVM RPC load by having the
*client* prove its own on-chain deposit with an `eth_getProof` state proof that
the guardians verify **cryptographically and deterministically** — instead of
the guardians polling `balanceOf` for every pending deposit every tick.

**Motivation:** Deposit detection today is `scan_pending_deposits`: for every
`PendingCheck` the guardians read `balanceOf(account)` every tick. With N
guardians on one RPC provider this is O(pending × ticks) calls concentrated on
a few keys — it exhausted a free Alchemy plan, then an Infura daily budget.
Clients are numerous and each only cares about its *own* address, so pushing
the chain-watching to clients shards the RPC load across many independent
endpoints (and, per testing, free **no-key** public endpoints support
`eth_getProof`, so clients need no API key at all). Verifying a proof also means
the guardians no longer trust their RPC's `balanceOf` answer — closing the
deposit facet of finding **sec-15** (RPC-trust) as a bonus.

## Established facts (verified 2026-07-29)

- **USDT `balances` mapping = storage slot 2.** A deposit account's balance
  lives at `key = keccak256(pad32(account) ‖ pad32(2))` in USDT's storage trie.
  (Confirmed empirically: `eth_getStorageAt(USDT, index(holder,2)) ==
  balanceOf(holder)` for a large holder; slots 0,1,3,4 were zero.)
- **MPT + header crates already in-tree:** `alloy-trie` (proof verification),
  `alloy-consensus` (block `Header` decode → `state_root`, header hashing),
  `alloy-rlp`. No hand-rolled Merkle-Patricia code.
- **Free no-key `eth_getProof` providers exist:** `ethereum-rpc.publicnode.com`,
  `1rpc.io/eth`, `eth.drpc.org` all return full account+storage proofs with no
  key. (cloudflare / llamarpc / ankr do not / now require a key.)

## Architecture (five pieces)

### 1. Federation light view — the agreed block-hash ring

The existing block poller (~1 RPC/tick) additionally reads the **block hash at
the confirmation-depth height** each tick. Guardians agree on it through the
normal consensus observation path and persist a **rolling ring** of the last
`BLOCK_HASH_RING_LEN` heights → hashes (target ≈ 300 ≈ 1 h at 12 s/block). This
ring is the *only* thing a proof is anchored to; it replaces all per-account
`balanceOf` polling. It is the irreducible federation EVM read for deposits: one
light `eth_getBlockByNumber` per tick, shared across all deposits, and
cross-checkable (each guardian can use a distinct provider, incl. free no-key
ones).

### 2. Client fetches the proof (its own RPC, no key)

The client already derives its deposit `account` (CREATE2) and holds the claim
key. To claim a deposit it:
1. picks a confirmed block `B` (≥ `confirmation_depth` deep) that is within the
   federation's ring window (learned from a new `latest_anchored_block`
   read-only endpoint, see §4);
2. computes `key = keccak256(pad32(account) ‖ pad32(2))`;
3. calls `eth_getProof(USDT_CONTRACT, [key], B)` and fetches block `B`'s header
   (RLP) — from any endpoint, defaulting to a free no-key public one, URL
   overridable;
4. submits `{ claim_pk, block_number: B, header_rlp, account_proof,
   storage_proof }` to the federation.

### 3. Deterministic verification in consensus (zero RPC)

A new API endpoint accepts the proof and enqueues it as a consensus item;
guardians verify it identically in the ordered apply path (pure computation, no
RPC, no wall-clock, no `our_peer_id`):

1. **Anchor:** `block_number` must be present in the agreed ring and
   `keccak256(header_rlp) == ring[block_number]`. This simultaneously (a)
   anchors trust to a hash the federation independently agreed on, (b) enforces
   confirmation depth (the ring only holds confirmed heights), and (c) rejects
   reorged/forged blocks (a non-canonical header won't match the agreed hash).
2. **State root:** decode `header_rlp` via `alloy-consensus` → `state_root`.
   (The header's other fields are not trusted beyond the hash match; only
   `state_root` is used.)
3. **Account proof:** verify `account_proof` (alloy-trie) against `state_root`
   for `keccak256(USDT_CONTRACT)` → the RLP account `[nonce, balance, storageRoot,
   codeHash]`; extract `storageRoot`. A proof of *absence* (empty account) →
   balance 0.
4. **Storage proof:** verify `storage_proof` against `storageRoot` for `key`
   → the stored balance word (proof of absence → 0).
5. **Credit:** apply the *existing* high-water-mark logic — credit
   `max(0, proven_balance − already_credited)` for `account`, exactly as
   `credit_deposit` does today (one-time-use address, monotonic `credited`).
   The proven balance is the deposit amount.

Because every guardian runs steps 1–5 on the same submitted bytes and the same
consensus ring, they all reach the identical credit with **no observe/vote
round** — strictly more deterministic than today's per-guardian observation
aggregation.

### 4. API + claim/sweep

- **New:** `submit_deposit_proof(DepositProof)` — enqueues the proof for
  consensus verification + credit (mirrors how `check_deposit` enqueues a
  `PendingCheck`, but the payload is a proof and the effect is a credit).
- **New (read-only):** `latest_anchored_block()` → the newest height in the
  ring (and the window depth), so the client knows which block to prove against.
- **Removed:** `check_deposit`, the `PendingCheck` scanner
  (`scan_pending_deposits` / `spawn_deposit_checker`), `gc_expired_pending_checks`.
- **Unchanged:** `claim` (mint e-cash for the credited amount) and the
  auto-sweep into the pool trigger on credit — the credit path is the only thing
  that changes.

### 5. DoS bounds

- `MAX_DEPOSIT_PROOF_BYTES` caps the submitted proof size (header + both proof
  node lists) — verification is CPU-bounded and a bad proof is simply rejected
  (no credit, no RPC amplification, unlike a client that could previously spam
  `check_deposit` to enqueue scans).
- Per-account submission throttle: reject a repeat proof for an `account` whose
  `credited` already covers the proven balance, or that was submitted within a
  small block window, so re-submits are cheap no-ops.
- Ring lookups + MPT verification are bounded by proof size and ring length; no
  unbounded loops.

## Data model changes

- **New:** `BlockHashRingKey(height: u64) → [u8;32]` (agreed canonical hash per
  confirmed height), pruned to `BLOCK_HASH_RING_LEN`.
- **New (consensus proposal plumbing):** guardians propose the observed
  confirmation-depth `(height, hash)` each tick (reuses the existing block-hash
  observation machinery from sec-12; the aggregation just additionally *persists*
  the agreed value into the ring rather than only using it transiently).
- **Removed:** `PendingCheck` / `PendingCheckKey` / scanning state.
- **Unchanged:** `DepositRecord` (the `credited` high-water mark) — reused as-is.

## Consensus version + migration

- `MODULE_CONSENSUS_VERSION` bump (new consensus item + removed
  endpoints/records).
- DB migration: drop any residual `PendingCheck` records (dead once the scanner
  is gone); introduce the empty `BlockHashRing` keyspace. Snapshot-tested like
  the other migrations.

## Client changes

- New `deposit-by-proof` flow in `fedimint-usdt-client`: derive account →
  (client waits for confirmations on its own RPC) → build proof request →
  `eth_getProof` + header fetch → `submit_deposit_proof` → poll `deposit_status`
  → `claim`.
- Configurable client EVM RPC URL, defaulting to a free no-key public endpoint;
  the client may race a small fixed list for redundancy. WASM-safe (uses the
  client's HTTP, not the server RPC layer).
- CLI: replace `check-deposit` with `submit-deposit-proof` (and a
  `--rpc-url` override); `deposit-address`, `claim`, `deposit-status` unchanged.

## Security analysis

- **Trust:** guardians no longer trust an RPC `balanceOf`; they verify a proof
  against a state root committed by a block hash they independently agreed on →
  **closes sec-15 for the deposit/amount facet.** Residual trust: the one block
  hash per tick that seeds the ring (a small, shared, cross-checkable surface;
  each guardian can use a different / free provider, and this is hardenable
  later with multi-provider agreement or header sanity checks — out of scope
  here).
- **Reorg safety:** a proof only verifies against a hash in the agreed ring;
  reorged blocks either never entered the ring or are pruned, and their
  headers won't match — so a deposit proven against an orphaned block cannot
  credit.
- **Preserved invariants:** confirmation depth (ring holds only confirmed
  heights), one-time-use deposit addresses, monotonic `credited` high-water
  mark, sweep-on-credit, threshold custody.
- **Griefing:** bounded — malformed/failed proofs are rejected with no RPC and
  no state growth beyond the size cap; the old `check_deposit`-spam →
  scan-amplification vector is removed entirely.

## Determinism

Proof verification is pure computation over the submitted bytes + the consensus
ring — no RPC, no wall-clock, no `our_peer_id`, no floats — so it belongs in the
deterministic apply path. The only RPC (the ring's block-hash read) stays in the
guardian-local observation task and enters consensus via the existing threshold
observation aggregation, exactly like today's block count.

## Testing strategy

- Unit: MPT verification against **captured real mainnet proofs** (fixtures from
  `eth_getProof` for a funded account and an empty account — proof-of-absence →
  0), header-hash mismatch rejection, wrong-slot rejection, oversize-proof
  rejection, high-water-mark crediting from a proof.
- Consensus: two guardians fed the same proof reach the identical credit;
  a proof against a non-ring / reorged height is rejected.
- Migration: snapshot test v(N)→v(N+1) dropping `PendingCheck`.
- e2e (anvil): deposit → client `eth_getProof` on anvil → submit → credit →
  claim → sweep, with **no guardian `balanceOf` poll** in the loop.

## Out of scope (explicitly)

- Withdrawal / UserOp receipt path (still uses RPC + bundler; separate concern).
- Multi-provider agreement / header-PoW sanity for the ring anchor (future
  sec-15 hardening).
- A federation-side "borrow a read" escape hatch for clients without any RPC
  (rejected: re-opens the concentration problem; free no-key endpoints remove
  the need).

## Open questions / risks

- **Header format across upgrades:** mainnet block headers gained fields over
  time (EIP-1559 baseFee, 4844 blob roots, etc.). Decoding must use a
  forward-compatible `Header` (alloy-consensus tracks current mainnet). We only
  read `state_root` + rely on `keccak(rlp)==agreed_hash`, so extra fields are
  fine as long as the RLP round-trips; verify against a *current* mainnet header
  fixture.
- **Ring window vs client latency:** `BLOCK_HASH_RING_LEN` must exceed the time
  a client needs to fetch a proof and submit; 300 blocks (~1 h) is generous.
  A client that misses the window just re-proves against a newer block.
- **Consensus-integration mechanism (plan decision):** the proof can enter
  consensus either as a **client transaction input** (`process_input` verifies
  the proof and credits — may compose with the existing `claim`/mint in one tx)
  or as a **guardian-proposed consensus item** driven by an API submit endpoint
  (mirroring how `check_deposit` records intent today). Both give a
  deterministic verify-and-credit; the plan picks whichever fits the existing
  claim/sweep transaction flow with the least new surface. This choice sets the
  final API shape (`submit_deposit_proof` endpoint vs. a proof input type).
