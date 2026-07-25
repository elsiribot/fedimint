# USDT-on-EVM module — security & trust model

Operator-facing summary of what this module trusts, what it deliberately
does **not** protect against, and what an operator/integrator must do about
it. This is a companion to `docs/usdt-module.md` (architecture) and
`docs/usdt-module-audit.md` (full threat model + accepted-risk register for
external auditors); this file exists so the load-bearing trust assumptions
and by-design limitations are not scattered across code comments only.
Findings referenced below (`sec-NN`) are from `security-review/`.

## Trust assumptions

### Per-guardian EVM RPC provider honesty and diversity (sec-15)

Deposit crediting and UserOp (sweep/withdrawal) settlement are both based on
answers from each guardian's configured EVM RPC endpoint: `balanceOf` reads
for deposits, and `eth_getUserOperationReceipt` for UserOp outcomes.
Consensus only accepts a *threshold* of guardians reporting the identical
observation, which is the normal Fedimint federation trust boundary — a
threshold of guardians can already violate custody/solvency in any module,
by design. That baseline (threshold collusion) is accepted, not a bug.

The **actionable** risk this module adds on top of that baseline is
operational: if a threshold of guardians happen to depend on the *same*
upstream RPC provider (or an attacker can MITM that shared path), a single
compromised/malicious provider can feed identical false answers to enough
guardians to fake a deposit or a UserOp outcome without any guardian
misbehaving. **Operators SHOULD configure distinct, independent RPC
providers per guardian** (not all guardians on the same Alchemy/Infura
account, and ideally not the same vendor) so no single upstream party can
unilaterally forge a threshold's worth of observations.

In-code defenses already in place that narrow this surface (they reduce the
blast radius of a bad/malicious RPC answer; they do not replace provider
diversity):
- **Chain-id startup check** (`check_chain_id_at_startup` in
  `modules/fedimint-usdt-server/src/lib.rs`, added for sec-17/sec-15):
  guardian startup hard-fails if the RPC endpoint's reported `chain_id`
  definitively disagrees with the federation's configured `chain_id`; a
  transient RPC error or timeout only warns.
- **EntryPoint log cross-check** (`get_user_op_receipt` in
  `modules/fedimint-usdt-server/src/rpc.rs`): a bundler's
  `eth_getUserOperationReceipt` is treated as a hint, not authoritative —
  the guardian additionally fetches the `UserOperationEvent` log directly
  from the configured `EntryPoint` via a single-block `eth_getLogs`, and
  requires the log's indexed `userOpHash` and address to match before
  proposing a `UserOpConfirmed` outcome.
- **Confirmation depth + block-hash binding** on both deposit observations
  and UserOp receipts: observations are proposed only once the relevant
  block is `confirmation_depth` blocks old, and votes carry a block hash so
  observations from different forks cannot aggregate into a threshold.
- **HTTPS required for non-loopback RPC** (`AlloyEvmRpc::new` in
  `modules/fedimint-usdt-server/src/rpc.rs`): a plaintext `http://` endpoint
  on a non-loopback host is refused at startup unless the operator
  explicitly opts in via `FM_USDT_UNSAFE_ALLOW_HTTP=1`, closing the most
  direct MITM vector against a remote RPC.

None of the above amounts to an independent state/light-client proof of the
RPC's answer (e.g. `eth_getProof`, a Merkle/state proof) — that remains a
possible future hardening, not something this module implements today.

### Setup-leader config-gen parameters (sec-17)

During distributed config generation, the setup leader supplies
consensus-critical parameters for this module: `usdt_contract`,
`entry_point`, `account_factory`, `simple_account_impl`, `chain_id`, and
`confirmation_depth`, among others. Every guardian receives these params and
can inspect them before agreeing to DKG; a malicious or mistaken leader
could still propose unsafe values (e.g. a wrong chain id or an unsafely
shallow confirmation depth for a live chain).

Bounds validation (`fedimint_usdt_common::validate_usdt_params`, invoked
both at config-gen and again in `ServerModuleInit::validate_config` as
defense-in-depth) rejects
some unsafe configurations outright — notably a `confirmation_depth` below
the module's minimum safe production depth on any non-dev chain id, unless
the operator explicitly acknowledges the override via
`FM_USDT_UNSAFE_LOW_CONFIRMATION_DEPTH=1`. This bounds-checking narrows but
does not eliminate the leader-trust surface (contract addresses, for
example, are validated for shape but not for correctness — a leader
supplying the *wrong but well-formed* `usdt_contract` address is not
detected). **Operators should independently verify the rendered gen params
before completing DKG**, not rely solely on the bounds check.

### Broadcaster hot key

Each guardian runs a broadcaster EOA (`FM_USDT_BROADCASTER_PRIVATE_KEY` /
the configured `broadcaster_private_key`) that fronts gas and relays signed
`UserOp`s to the bundler/EntryPoint. This key is a hot key with real
operational responsibility, but it **cannot move federation funds**: all
deposit and pool accounts are `SimpleAccount`s owned by the DKG group public
key, and every `UserOp` must carry a valid threshold signature over that
group key before `EntryPoint` will execute it. Compromise of a broadcaster
key enables gas griefing (spending the guardian's ETH) or relay withholding
(refusing to submit/allowing ops to stall), not theft — any guardian's
broadcaster may submit a given op, so relay withholding by one broadcaster
does not block progress by itself. Treat it with the operational care due a
hot wallet: fund it minimally, monitor its balance, and prefer the
file-based secret fallback below over the process environment.

## By-design limitations (with operator mitigations)

### Deposit addresses are one-time-use; re-deposits to a swept address strand funds (sec-20)

Deposit crediting uses a raw-balance high-water mark: `DepositRecord.credited`
only ever increases, gated on the account's *current* on-chain balance
exceeding the previous credited amount (`credit_deposit` /
`scan_pending_deposits` in `modules/fedimint-usdt-server/src/lib.rs`). Once a
deposit has been credited and fully swept, the account's on-chain balance
returns to zero while `credited` (and `swept`) stay at the old total. A
later transfer to that same address is invisible to the protocol unless it
exceeds the old high-water mark, and even then only the excess above that
mark becomes credited/sweepable — the address does not "reset."

**This is a documented, accepted limitation for this effort, not a bug
fix candidate.** Deposit addresses are intended to be used exactly once.
**Integrations and UIs MUST allocate a fresh deposit address per deposit
(the client's `allocate_deposit` already does this by default) and must
never present a previously-used deposit address to a user for a second
deposit.** There is currently no in-protocol recovery path for funds sent to
an already-swept address; recovering them requires coordinated, manual,
out-of-band guardian action outside this module. A useful (not yet
implemented) operator tool would surface a "stuck/reused address" condition
(on-chain balance > 0 while `credited == swept` for that account) so support
staff can detect and manually remediate it.

### Broadcaster fronts ETH while fees accrue in USDT; no on-chain reimbursement (sec-22)

All `UserOp`s currently run without a paymaster
(`paymaster_and_data: Vec::new()` in the sweep/withdrawal builders); the
guardian's broadcaster EOA fronts real ETH for the EntryPoint prefund and
`handleOps` gas. Deposit and withdrawal fees, in contrast, are charged and
accrue in USDT to the pool. There is no protocol-level or on-chain path that
converts pooled USDT fee revenue into ETH reimbursement for the
broadcaster.

**Operators MUST monitor broadcaster ETH balances and top them up
out-of-band.** The module's bootstrap readiness check
(`broadcaster_funded`, gated on the config-gen param
`broadcaster_min_balance_wei`, default 0.05 ETH) will report the federation
not-ready if a guardian's broadcaster balance falls below that threshold,
which gives an operational signal before the broadcaster runs dry — but it
is a readiness gate, not automatic replenishment. The dust-deposit sweep
gate (sec-02: `maybe_trigger_sweep` refuses to sweep unless the amount
credited to the user, net of the deploy+sweep gas fee, would be strictly
positive) limits how much of this ETH can be drained by spam deposits that
are never claimed, but it does not address the underlying economics gap for
legitimate traffic.

## Secrets handling

`FM_USDT_BROADCASTER_PRIVATE_KEY` and `FM_USDT_EVM_RPC_API_KEY` are secrets.
Passing secrets as plain environment variables makes them visible to other
same-user processes via `/proc/<pid>/environ`; both now support a
file-based fallback, mirroring the repo's existing `_FILE` convention (see
`fedimintd`'s bitcoind password handling):

- `FM_USDT_BROADCASTER_PRIVATE_KEY_FILE` — path to a file whose (trimmed)
  contents are the broadcaster private key.
- `FM_USDT_EVM_RPC_API_KEY_FILE` — path to a file whose (trimmed) contents
  are the RPC API key.

Resolution order (`env_secret_or_file` in `fedimint-core/src/envs.rs`): the
inline `_ENV` var wins if set to a non-empty value; otherwise the `_FILE`
var is read (trimmed) if set; otherwise there is no override and the
module falls back to whatever is configured elsewhere (e.g.
`broadcaster_private_key` in the encrypted private config, or no API key
appended to the RPC URL). Only *which* source supplied the secret is
logged, at `debug`; the secret value itself is never logged.

Independent of the above, RPC URLs and any embedded API key are redacted in
`Debug` output, logs, and error messages (`redact_rpc_url` /
`impl Debug for AlloyEvmRpc` in `modules/fedimint-usdt-server/src/rpc.rs`,
sec-18), and a remote (non-loopback) `http://` RPC endpoint is refused at
startup unless explicitly overridden (see the RPC provider section above).

## Client claim/refund keys (misc #9)

The client stores deposit claim keypairs and withdrawal refund keypairs in
its local database in plaintext (`ClaimKeyKey` / `RefundKeyKey` in
`modules/fedimint-usdt-client/src/db.rs`, values are raw `Keypair`s — the
client database has no separate secrets vault for these). This is
acceptable because both key families are **deterministic functions of the
client's module root secret and a seed-derivation index** (see
`claim_keypair_for_index` / the withdrawal refund keypair derivation in
`modules/fedimint-usdt-client/src/lib.rs`): they are recoverable from the
seed alone (plus, for uncredited deposits, a fresh federation scan — see
`recover_deposits`), not solely from the on-disk DB. Integrators should
still be aware that **the client DB is not a secret-free artifact**: anyone
with read access to it can reconstruct spending authority over any
deposit/refund account it has recorded, exactly as they could with the seed
itself. Treat client DB backups with the same care as the seed.
