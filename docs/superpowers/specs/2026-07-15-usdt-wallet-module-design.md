# USDT Wallet Module for Fedimint — Design

**Status:** Draft for review
**Date:** 2026-07-15
**Author:** (brainstormed with Claude Code)
**Scope:** Feasibility + architecture for a new Fedimint wallet module custodying USDT on EVM chains. This document is the design; a separate implementation plan follows.

---

## Executive summary

Fedimint today custodies **Bitcoin**. Its elegance rests on one property of the UTXO model: **on-chain fees are just `inputs − outputs`, deducted from the federation's own BTC**, so the federation only ever holds a single asset and can pay its own withdrawal fees "from inside" the multisig. We want to add **USDT** as a federated asset. Two properties of USDT-bearing chains break the Bitcoin model:

1. **Gas is paid in a different asset.** Sending USDT (ERC-20/TRC-20) requires native gas (ETH), which cannot be paid in USDT at the base protocol. A naive design forces the federation to custody and manage a second "gas" asset.
2. **A multisig cannot pay its own gas.** On EVM the transaction-initiating account must be an externally-owned account (EOA) holding ETH; a contract/multisig cannot be the top-level fee payer. And a bare EOA is single-key — it cannot carry an n-of-m script the way a Bitcoin address can.

**This design targets EVM chains and solves both problems with two pieces of machinery Fedimint does not currently have:**

- **Threshold ECDSA (MPC).** The federation holds one *group* secp256k1 key as secret shares and produces a single ordinary signature from t-of-n guardians. This replaces Bitcoin's script-multisig for account-model chains, and — via additive key/address derivation — gives unlimited federation-controlled addresses from one distributed key, with no per-user key management.
- **ERC-4337 account abstraction with an ERC-20 paymaster.** Deposit addresses are **counterfactual smart accounts** (CREATE2 addresses committing to a user's claim key). A **paymaster** pays ETH gas and is **reimbursed in USDT from the same funds being moved** — recovering the "fee from inside the asset" property. A **bundler** batches consolidations and withdrawals.

**The resulting user-visible flow mirrors Fedimint's Bitcoin wallet:**

- **Deposit:** user sends a plain USDT transfer (one tx, user pays their own gas) to a unique per-user address that commits to their claim key.
- **Claim:** the federation observes the deposit via consensus and mints e-cash bound to the claim key. **Gasless and on-chain-free**, exactly like a Bitcoin peg-in.
- **Consolidation:** the federation batches deposits into a pooled smart account; the paymaster covers gas in USDT.
- **Withdrawal:** the federation threshold-signs a transfer to the recipient; the paymaster covers gas in USDT.

**Net result:** the federation custodies **only USDT**. The residual departure from Bitcoin is a **liveness/censorship/pricing dependency on a paymaster** — explicitly *not* a custody trust, since every move is authorized by the federation's threshold signature and the paymaster can only refuse service or collect its fee. This is mitigated by supporting multiple paymaster providers plus a **self-run paymaster + ETH float fallback**.

**Primary trade-off accepted:** two significant new subsystems (threshold ECDSA, ERC-4337 integration) and a mild non-custodial dependency on gas-relaying infrastructure, in exchange for reaching USDT's deep liquidity on EVM while keeping the federation single-asset.

---

## 1. Background and motivation

### 1.1 How Fedimint's Bitcoin wallet works today

The existing wallet module (`fedimint-wallet-common` / `-client` / `-server`) establishes the template a new asset module must fill:

- **Custody:** a descriptor multisig `wsh(sortedmulti(t, [peer keys]))`. Each guardian holds its own secp256k1 key; Bitcoin script enforces the t-of-n threshold.
- **Per-user deposit addresses via pay-to-contract tweaking:** one tweakable key yields unlimited addresses (`address_i = descriptor.tweak(tweak_i)`), and the federation can later sign for each with `secret_key + tweak_i`. No per-user key storage — only the tweak is recorded alongside the resulting UTXO.
- **Deposit (peg-in):** a background monitor watches derived addresses; the client submits a `PegInProof` (a Merkle inclusion proof); the server verifies it against a consensus-agreed block height (after a finality delay) and mints e-cash. Claiming records a `SpendableUTXO { tweak, amount }` — it does **not** move funds on-chain.
- **Withdrawal (peg-out):** the server does deterministic coin selection across UTXOs, builds a PSBT, and guardians contribute threshold signatures **as consensus items** (`WalletConsensusItem::PegOutSignature`) until the threshold is met; the finalized transaction is broadcast. Fees are the input−output delta, paid in BTC from inside the multisig.
- **Consensus over external chain state:** guardians vote on `BlockCount` and `Feerate` via consensus items; the module reads the chain through the `IServerBitcoinRpc` trait.

### 1.2 Why USDT breaks this

| Property | Bitcoin (today) | USDT on EVM |
| --- | --- | --- |
| Fee asset | BTC (the custodied asset) | ETH (a *second* asset) |
| Fee location | `inputs − outputs`, from inside the spend | An external EOA must pre-hold ETH and pay gas |
| Multisig pays its own fee? | Yes | No — a contract can't be the top-level gas payer |
| n-of-m on one address? | Yes (Bitcoin script) | No (bare EOA is single-key; needs MPC or a contract) |
| Combine many deposits in one tx? | Yes (multi-input UTXO tx) | **No** — one `from` per tx; each source needs its own transfer + gas |

The last row is the sharpest account-model constraint and is why deposit **consolidation** (not just withdrawal) is a first-class concern in this design.

### 1.3 Chain choice

We target **EVM chains** (Ethereum L1 and EVM L2s such as Arbitrum/Base/Optimism). Rationale:

- Deep USDT liquidity and real payment demand (the stated success criterion).
- ERC-4337 account abstraction is standardized and productized on EVM, giving a clean "gas paid in USDT" path.
- Threshold-ECDSA custody is chain-portable across all EVM chains, so the same core works on L1 and any L2 — a per-chain adapter selects RPC, chain id, and paymaster/bundler endpoints.

Tron and Liquid were considered and are documented under **Alternatives considered** (§8). Tron has higher raw USDT volume and a cheaper staked-energy fee model, but weaker account-abstraction tooling; Liquid maps most cleanly onto the existing UTXO wallet but has thin L-USDt liquidity and stacks a federation on Liquid's own federation. Both are out of scope for the first implementation but the module boundaries are drawn so a Tron adapter is a plausible later addition.

---

## 2. Goals and non-goals

### Goals

- Custody USDT on EVM chains under an existing Fedimint federation's t-of-n trust model.
- Federation holds **only USDT** in the steady state (no guardian-managed ETH float required in the primary design).
- Deposits and claims are **gasless for the federation** and cheap/one-transaction for the user.
- Withdrawals pay gas **in USDT** via a paymaster.
- Reuse Fedimint's module patterns (`ServerModule`/`ClientModule`, consensus items, three-crate layout) as closely as the account model allows.
- No new **custodial** trust: every fund movement is authorized by the federation threshold signature.

### Non-goals (for the first version)

- Tron and Liquid support (documented as future adapters, not built).
- Confidential/shielded balances.
- Cross-chain USDT bridging between the supported chains.
- Supporting arbitrary ERC-20s (USDT-specific quirks are handled; generalization is later).
- Eliminating the paymaster liveness dependency entirely (mitigated, not removed).

---

## 3. Chosen architecture

### 3.1 Component overview

Three crates, following the module pattern:

- `fedimint-usdt-common` — shared types: config (group public key, chain id, USDT contract address, paymaster config), consensus item types, input/output types, deposit-claim proof types, encoding.
- `fedimint-usdt-server` — the `ServerModule`: threshold-ECDSA signing shares, chain observation, deposit detection consensus, consolidation and withdrawal transaction construction, paymaster interaction.
- `fedimint-usdt-client` — the `ClientModule`: deposit-address derivation, claim submission, withdrawal requests, state machines.

New cross-cutting subsystems:

- **Threshold ECDSA signer** — a distributed secp256k1 signing service (see §3.2). Likely its own crate (`fedimint-threshold-ecdsa`) so it can be reused.
- **EVM chain adapter** — an `IServerEvmRpc`-style trait mirroring `IServerBitcoinRpc`: block height, logs/receipts, account balances, gas price, submit transaction / submit UserOperation, chain id. Per-chain implementations behind one trait.

### 3.2 Custody: threshold ECDSA group key

- During DKG, guardians run a distributed key generation for a **single group secp256k1 key**; each guardian holds a secret share. The group public key is in consensus config.
- Signing produces a **single standard ECDSA signature** from t-of-n guardians — indistinguishable on-chain from a normal EOA signature.
- **Protocol choice: a modern, audited threshold-ECDSA protocol — CMP (MPC-CMP) or DKLs23-class.** We explicitly **avoid GG18/GG20** (CVE-2023-33241 "BitForge", exploited across 10+ custody products) unless a fully-patched, audited implementation is used.
- **Additive derivation:** child keys/addresses derive as `groupPubKey + tweak·G`, letting one group key own many accounts. This composes with CMP/DKLs additive tweaks. (Analogous to the Bitcoin wallet's tweak, but producing a single signature instead of a script multisig.)

The group key is the **owner/signer** of the ERC-4337 smart accounts described next.

### 3.3 Deposit addresses: counterfactual ERC-4337 smart accounts

- Each user's deposit address is a **CREATE2 counterfactual smart-account address**, derived deterministically from `(factory, group key, salt)` where **`salt` commits to the user's claim public key**. The address is fully determined before any contract is deployed and costs nothing until first use.
- **Why smart accounts, not bare EOAs:** a smart account can (a) be operated via ERC-4337 `UserOperation`s that a paymaster sponsors, and (b) pay the paymaster in USDT from its own balance. A bare EOA cannot — it must hold ETH and pay its own gas, forcing an ETH float and per-address pre-funding.
- The account's authorized signer is the federation **group key** (or a per-account tweak of it). The **claim key** committed in the salt is a *separate* key the user holds; it authorizes minting e-cash, not on-chain movement (see §3.4).

**Deposit → user association** is therefore by **address**, not by an on-chain memo (ERC-20 transfers carry no memo, unlike XRP/Stellar/TON): the deposit address itself commits to the claim key. This cleanly separates:

- **Detection** — trusted to guardian consensus (they observe the balance / transfer log at the address), and
- **Authorization to claim** — cryptographically enforced (only the holder of the claim private key can mint the resulting e-cash).

### 3.4 Deposit and claim flow (gasless for the federation)

1. Client derives its deposit address from the federation config + its own claim key, and displays it.
2. User sends a **plain USDT transfer** to that address — one transaction, user pays their own gas. (ERC-20 balances may sit at an address with no deployed code; deployment happens later, on first consolidation.)
3. Guardians observe the incoming transfer via the EVM adapter and **vote via a consensus item** (`UsdtConsensusItem::Deposit { address, amount, block }`) once past a configured **confirmation depth**. Consensus credits the deposit to the committed claim key.
4. The client submits a **claim** proving control of the claim key (a signature over the operation). The server mints e-cash bound to it. **No on-chain action, no gas** — the USDT remains at the deposit address, part of a *virtual pool*.

This mirrors the Bitcoin peg-in: claiming records spendable value; it does not move funds.

> **Deposit detection trust model.** Because EVM has no lightweight client-submittable SPV proof comparable to Bitcoin's `TxOutProof`, detection is by **guardian consensus over observed chain state** (each guardian runs/queries a full node and votes, exactly as they already vote on block height). This shifts deposit *detection* fully to the guardians. Authorization to claim remains cryptographic, so a dishonest minority cannot steal deposits, but a dishonest **threshold** could in principle fabricate or withhold a deposit vote — the same trust already extended to guardians for block-height consensus. A heavier Merkle-Patricia state/receipt-proof scheme is possible later to reduce this, at significant complexity; it is out of scope for v1.

### 3.5 Consolidation flow (batched, paymaster-funded)

The virtual pool is fragmented across many deposit addresses. Account-model chains cannot spend many addresses in one transaction, so consolidation is explicit:

1. The server selects a batch of confirmed, claimed deposit addresses (skipping never-withdrawn dust below a threshold).
2. For each, it constructs a `UserOperation` that, on first use, **deploys the smart account (CREATE2 `initCode`)** and **transfers its USDT to the pooled smart account**.
3. A **paymaster** covers ETH gas and is **reimbursed in USDT deducted from the moved funds** — the "fee from inside the asset" analog. A **bundler** batches the UserOperations into one on-chain transaction.
4. Each UserOperation is authorized by a **threshold-ECDSA signature** contributed by guardians as consensus items (mirroring `PegOutSignature`).

Consolidation is **batch-timed** (every N deposits / N minutes / when gas is favorable), not strictly per-deposit, to amortize per-tx overhead.

### 3.6 Withdrawal flow

1. Client submits a withdrawal output (`recipient`, `amount`).
2. The server ensures the pool has sufficient consolidated balance (triggering consolidation if needed) and constructs a `UserOperation` transferring USDT from the pooled account to the recipient.
3. Guardians contribute threshold-ECDSA signatures via consensus items until the threshold is met.
4. The paymaster covers gas **in USDT** (deducted from the withdrawal or the pool per policy); the bundler submits it.
5. On confirmation past the confirmation depth, the outcome (tx hash) is recorded and the client is notified.

**Fee accounting:** the user-visible withdrawal fee must cover (a) the paymaster's USDT-denominated gas cost plus markup and (b) a module fee. Because gas is volatile and priced by the paymaster at execution, the module quotes a fee with a bounded buffer, analogous to how the Bitcoin wallet quotes `PegOutFees`.

### 3.7 Gas model — the three options, and the recommendation

The paymaster still needs *someone* to hold ETH and front gas. Three ways to arrange that:

| Model | Who fronts ETH | Federation holds ETH? | Trust added | Notes |
| --- | --- | --- | --- | --- |
| **A. Third-party paymaster (recommended primary)** | External paymaster service (Pimlico, Biconomy, Alchemy Gas Manager, ZeroDev, Candide, …) | No | Liveness / censorship / pricing — **not custody** | Standardized ERC-20 paymaster; federation pays in USDT. Mitigate with **multiple providers**. |
| **B. Self-run paymaster + ETH float (recommended fallback)** | The federation's own paymaster contract, funded from a guardian-managed ETH float | Yes (a float) | None external | Removes the liveness dependency; reintroduces second-asset management and a float top-up process (swap USDT→ETH periodically). |
| **C. Bare-EOA + ETH pre-funding (documented, not recommended)** | Federation ETH float pre-funds each deposit EOA | Yes | None external | No ERC-4337; simplest contracts, but clunky (dust, 2 txs per sweep), no gas-in-USDT, heavy float management. This is the "if AA proves impractical" escape hatch. |

**Recommendation:** ship **A with B as an always-available fallback**. Configure a primary third-party paymaster and a self-run paymaster; if the third party is unavailable or over-prices, guardians fall back to the self-run paymaster and ETH float. This keeps steady-state custody single-asset while guaranteeing withdrawal liveness. Model C is retained only as a contingency if ERC-4337 integration proves impractical on a target chain.

### 3.8 Consensus over external chain state

Reusing the Bitcoin wallet's pattern, the module proposes and agrees on:

- `UsdtConsensusItem::BlockCount(u64)` — observed head, median-voted, used with a confirmation depth.
- `UsdtConsensusItem::GasPrice(...)` — for fee quoting.
- `UsdtConsensusItem::Deposit { address, amount, block }` — observed deposits (§3.4).
- `UsdtConsensusItem::WithdrawalSignature { op_hash, share }` and `ConsolidationSignature { op_hash, share }` — threshold-ECDSA signature shares (mirroring `PegOutSignature`).
- `UsdtConsensusItem::ModuleConsensusVersion(...)` — version voting.

### 3.9 Mapping onto Fedimint traits

| Fedimint concept | USDT module realization |
| --- | --- |
| `ServerModule::consensus_proposal` | Propose block count, gas price, observed deposits, pending signature shares |
| `ServerModule::process_consensus_item` | Fold in peer votes; advance median head; assemble threshold signatures; finalize UserOps |
| `ServerModule::process_input` | Consume a **claim** of a detected deposit → mint e-cash bound to the claim key |
| `ServerModule::process_output` | Consume a **withdrawal** request → enqueue a paymaster-funded transfer |
| `IServerBitcoinRpc` | New `IServerEvmRpc` trait: head, logs, balances, gas price, submit tx / UserOp, chain id |
| Descriptor multisig + PSBT | Threshold-ECDSA group key + ERC-4337 `UserOperation`s |
| `PegInProof` (client-submitted) | Consensus-observed deposit + client **claim signature** (no SPV proof in v1) |
| `SpendableUTXO { tweak, amount }` | `DepositRecord { address, claim_key_commitment, amount }` (virtual pool entry) |

---

## 4. Data and state (server DB, sketch)

- `DepositAddressKey(address) -> DepositRecord` — detected/claimed deposits forming the virtual pool.
- `ClaimedKey(claim_commitment) -> ()` — replay protection for claims.
- `BlockCountVoteKey(peer) -> u64`, `GasPriceVoteKey(peer) -> ...` — per-guardian votes.
- `PendingUserOpKey(op_hash) -> PendingUserOp` — consolidation/withdrawal UserOps awaiting signatures.
- `UserOpSignatureShareKey(op_hash, peer) -> Share` — collected threshold shares.
- `SubmittedUserOpKey(op_hash) -> SubmittedUserOp` — broadcast, awaiting confirmation.
- `PoolAccountKey -> PoolState` — pooled smart-account address and tracked balance.

---

## 5. Key risks and open questions

1. **Threshold ECDSA is new to Fedimint and cryptographically fragile.** Requires a modern audited protocol (CMP/DKLs), careful DKG, and additive-tweak support. This is the single largest engineering and security risk. *Open:* build vs. integrate an existing audited library; wasm/client compatibility for any client-side signing.
2. **ERC-4337 surface area.** Requires an audited smart-account wallet, correct handling of counterfactual deployment, and robust bundler/paymaster integration. *Open:* which account implementation (e.g. a minimal audited wallet) and whether to depend on a specific EntryPoint version.
3. **USDT's non-standard ERC-20.** `approve` must be zeroed before re-setting, no return value, **no `permit`**. Paymaster reimbursement and any approvals must handle these quirks; some providers support USDC more smoothly than USDT. *Open:* confirm chosen paymaster's USDT support per chain.
4. **Paymaster liveness/pricing.** Third-party dependency; mitigated by multi-provider + self-run fallback, but withdrawal fee quoting must tolerate volatile, execution-time gas pricing.
5. **Deposit-detection trust.** Detection rests on guardian consensus (no SPV proof). Acceptable given the existing block-height trust, but weaker than Bitcoin's client-verifiable proof; a state-proof scheme is a possible later hardening.
6. **Reorg / finality handling.** Confirmation depth must be chosen per chain; L2 reorg/sequencer-failure semantics differ from L1 and need per-adapter policy.
7. **ETH-float management (fallback path).** If/when the self-run paymaster is used, guardians must periodically swap USDT→ETH to top up the float — an operational process and a small second-asset exposure.
8. **Migration/versioning & wasm.** Client module must build for wasm; threshold-ECDSA client interactions (if any) must be wasm-compatible.

---

## 6. Fallback variant (summary)

If ERC-4337 integration proves impractical on a target chain, fall back to **Model C** (§3.7): bare-EOA deposit addresses controlled by the threshold key, with the federation pre-funding each address's gas from an ETH float and sweeping via ordinary transfers. This loses gas-in-USDT and single-asset custody and is operationally heavier, but requires no smart-account infrastructure. It is a contingency, not the target.

---

## 7. High-level implementation phases

(Full step-by-step plan to be produced separately.)

0. **MPC library spike (1–2 weeks)** — select the threshold-ECDSA library (CGGMP21/DKLs-class, audited; verify t-of-n, additive/HD derivation, identifiable aborts, transport abstraction) and prototype one threshold signature end-to-end through a Fedimint-compatible transport. Resolves the largest source of estimate variance before deeper investment.
1. **Threshold ECDSA subsystem** — DKG, signing, additive tweaks; integrate the audited library selected in the spike; tests.
2. **EVM chain adapter** — `IServerEvmRpc` + one concrete implementation (an L2 first, for cheap gas during development); consensus over head/gas price.
3. **Common crate** — config, consensus items, input/output and claim types, encoding.
4. **Deposit path** — counterfactual address derivation, detection consensus, gasless claim → mint.
5. **ERC-4337 integration** — smart-account wallet, paymaster + bundler clients, UserOp construction and threshold signing.
6. **Consolidation** — batched, paymaster-funded sweeps into the pool.
7. **Withdrawal** — paymaster-funded transfers, fee quoting, outcome tracking.
8. **Fallback gas model (B/C)** — self-run paymaster + ETH float; bare-EOA contingency.
9. **Integration tests** — devimint-based end-to-end against an EVM test node / testnet.

---

## 8. Alternatives considered

- **Deposit contract carrying a claim-pubkey memo (single pooled account).** Rejected as the primary because it needs an audited contract per chain *and* a two-transaction (`approve` + `deposit`) deposit UX. The counterfactual-smart-account approach gives the same single-pool/association benefits with a one-transaction plain-transfer deposit. (The pooled account still exists in our design — as the consolidation target — but users deposit to per-user addresses, not a shared one.)
- **Per-user bare EOAs controlled by the threshold key (no AA).** Clean deposits, but consolidation/withdrawal requires ETH in each address and per-address gas, forcing an ETH float and clunky sweeps. Retained only as the Model C fallback.
- **Gnosis Safe contract multisig.** Its `gasToken` refund is an elegant "pay relayer in USDT" analog, but per-user Safes are deploy-heavy and Safe is EVM-only. Threshold ECDSA is lighter on-chain (single signature), chain-portable, and address-stable. Considered for the pooled account but not required given the paymaster model.
- **Tron (TRC-20).** Highest USDT volume and a staked-energy fee model that makes consolidation cheap, but weaker account-abstraction tooling and a different multisig model. A strong future adapter; out of scope for v1.
- **Liquid (L-USDt).** Technically the closest fit to the existing UTXO wallet (native multi-input spends, Bitcoin-style script multisig, fee self-funded by swapping L-USDt→L-BTC), but thin liquidity and a federation-on-federation trust stack. Out of scope for v1; the module boundaries do not preclude a later Liquid module.

---

## 9. Summary of trust departures from Bitcoin custody

| Dimension | Bitcoin wallet | This design |
| --- | --- | --- |
| Assets custodied | BTC only | USDT only (steady state) |
| Fee source | From inside the spend | Paymaster, reimbursed in USDT from the spend |
| Fund-movement authority | Guardian threshold (script multisig) | Guardian threshold (threshold ECDSA) — unchanged in spirit |
| Deposit detection | Client-verifiable SPV proof | Guardian consensus (no client proof in v1) |
| External dependency | Bitcoin full nodes | Bitcoin-equivalent EVM nodes **+ paymaster/bundler** (liveness/pricing, non-custodial) |

The design preserves Fedimint's core custody trust (guardian threshold authorizes every move) while accepting a **non-custodial** gas-relaying dependency and a **consensus-based** deposit-detection model as the price of operating on an account-model chain.

---

## 9.1 Decision record addendum (2026-07-15, after planning research)

Settled with elsirion during master planning (full rationale in `docs/superpowers/plans/2026-07-15-usdt-evm-module-master-plan.md`):

- **Runtime MPC transport:** CGGMP21 signing rounds ride **consensus items** (like peg-out signatures today), full-interactive, P2P round parts encrypted per-recipient. ~15–60 s per signing session; withdrawals batch into one UserOp per session. No core-framework changes; no presignature pool (avoids the presig-reuse key-leak hazard). Fedimint exposes no runtime guardian-to-guardian channel to modules, so the alternatives were a public-API side channel or a core extension — both rejected for v1.
- **Setup-time DKG:** CGGMP21 keygen + aux-gen run over `PeerHandleOps::exchange_bytes` broadcast rounds during config gen (per-recipient-encrypted payloads packed into each round). Note: `fedimint-testing` only exercises trusted-dealer config gen, so real DKG needs its own harness over the fake p2p mesh.
- **AA stack:** SimpleAccount + EntryPoint v0.7, vendored bytecode. Per-deposit addresses come from **CREATE2 salts committing to the claim key** — HD derivation is off the critical path (retained only for the bare-EOA fallback Model C).
- **Deposit watching:** **claim-triggered verification** — no standing watch set; the client requests a check after depositing (`check_deposit`), guardians verify the account balance at a confirmation-depth-anchored block and vote identical observations to threshold.
- **Denomination (deployment constraint):** Fedimint transactions balance in a single unit federation-wide, so this module implies a **USDT-denominated federation** (mint issues USDT e-cash; 1 `Amount` unit ≡ 10⁻⁶ USDT). Mixed BTC+USDT federations are out of scope — multi-asset support would be a deep core change.
- **Fee/FX pricing:** guardians vote `{max_fee_per_gas, usdt_per_eth}` from per-guardian-configured sources; median-of-votes, mirroring today's bitcoin feerate votes.

---

## 10. Effort estimate

Basis: one strong senior Rust engineer using AI coding tools heavily, **integrating an existing audited threshold-ECDSA library** (CGGMP21/DKLs-class) rather than building the primitive. Engineer-weeks; wide error bars.

| Workstream | Weeks | Notes |
| --- | ---: | --- |
| Threshold ECDSA (integrate library, DKG, signing, tweaks) | 5–8 | Work is the multi-round-MPC ↔ Fedimint-consensus integration, presigning, abort handling — not the crypto itself |
| ERC-4337 integration (smart account, paymaster, bundler, UserOps) | 4–8 | Integration-debug-heavy; USDT ERC-20 quirks |
| Common crate + module plumbing | 3–5 | |
| Deposit path (addresses, detection consensus, claim→mint) | 3–5 | |
| EVM chain adapter | 2–4 | |
| Withdrawal (fee quoting, signing, outcome tracking) | 2–4 | |
| Consolidation (batched sweeps) | 2–4 | |
| Integration tests / devimint | 3–6 | |
| Fallback gas model (self-run paymaster + ETH float) | 2–4 | Deferrable past MVP |
| Hardening + audit prep/remediation | 3–5 | Primitive pre-audited → smaller audit scope |

**Milestones:** testnet MVP ≈ **4.5–6 months**; audited mainnet-ready ≈ **7.5–10 months** (external audit adds ~4–8 weeks calendar). For comparison, a Liquid (L-USDt) variant is estimated at roughly **40–50% of this effort** (no MPC, no ERC-4337, no consolidation subsystem).

**Top risks after the library assumption:** (1) interactive-MPC ↔ consensus integration (presigning, guardian churn, abort handling); (2) library fit; (3) ERC-4337/paymaster friction with USDT specifically.

**Library selection (resolved 2026-07-15):** `cggmp21` (LFDT-Lockness, ex-Dfns) — MIT/Apache-2.0, Kudelski-audited, maintained, arbitrary t-of-n, SLIP-10 HD derivation (signs for derived child keys from the same shares, replacing the additive-tweak requirement), presigning, transport abstracted via `round_based::Delivery`. Known gap: **no identifiable aborts** — a stalled/malicious signer cannot be cryptographically blamed; mitigate with per-peer round timeouts and rotating the signing subset (t < n). Alternatives rejected: synedrion (AGPL, unaudited), sl-dkls23 (non-commercial license), 0xCarbon DKLs23 (unaudited), ZenGo multi-party-ecdsa (unmaintained, vulnerable lineage).
