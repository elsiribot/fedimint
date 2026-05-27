# fedimint-bench

A throughput / latency benchmark driver for a Fedimint federation. Submits
mint payment transactions at a configurable target TPS and measures
end-to-end latency from API submission through consensus inclusion and
threshold-signed output finalization.

## What it does

Each bench transaction is a single **mint payment**: the bench picks a
payment amount, calls `MintClientModule::create_output` to decompose it into
tier-denominated notes (same `represent_amount` logic real clients use), then
lets the wallet balancer pick inputs and add change. So every tx exercises
the consensus + threshold-signing path with a realistic shape — multiple
inputs, multiple user outputs, and balancer change.

To drive throughput beyond what a single client can sustain (≈ 1 /
federation-round-trip TPS), the bench spawns N **worker clients**, each with
its own DB. Each worker submits strictly sequentially — needed because a
single client's state machines panic on `RocksDB WriteConflict` when many
in-flight ops race for the wallet ledger.

For each tx the bench records:
- accepted latency (API submit → consensus inclusion)
- finalized latency (API submit → all outputs threshold-signed)
- user-added output count
- balancer change output count
- payment amount (so you can confirm the distribution you actually drove)

## Running against a fresh devimint federation

The included script wraps `devimint dev-fed --exec` so you don't have to
manage the federation lifecycle:

```bash
nix develop
export CARGO_PROFILE=release
cargo build --workspace --all-targets --profile release

RESULT_DIR=/tmp/bench-run \
DURATION_SECS=30 \
CARGO_PROFILE=release \
./fedimint-bench/scripts/run-against-devimint.sh 1:1 2:2 5:4 10:8 20:16 40:32
```

Each `<tps>:<workers>` pair is one sweep step. The script writes a JSON
report and a log per step to `$RESULT_DIR/`.

Script env overrides:
| Env | Default | Meaning |
|---|---|---|
| `RESULT_DIR` | `target-nix/bench-results` | where reports + logs land |
| `DURATION_SECS` | `20` | per-step bench duration |
| `PAYMENT_MSATS` | `10000` | min payment per tx, in msat |
| `PAYMENT_MAX_MSATS` | `1000000` | max payment per tx; unset → fixed amount |
| `CARGO_PROFILE` | `dev` | `release` strongly recommended for representative numbers |

The script wipes `$RESULT_DIR/workers-db` at the top of each run so cached
client config from a stale federation can't poison the new session.

## Running against an already-running federation

If you're already inside a devimint shell (`just devimint-env`), invoke the
binary directly — `FM_INVITE_CODE` and the iroh connection-override env
vars are picked up automatically:

```bash
fedimint-bench --target-tps 10 --workers 8 --duration-secs 30
```

## Key flags

| Flag | Default | Notes |
|---|---|---|
| `--target-tps` | (required) | combined TPS across the worker pool |
| `--workers` | `4` | parallel clients; raise to drive higher TPS |
| `--duration-secs` | `60` | steady-state bench duration |
| `--payment-amount-msats` | `10000` | per-tx payment (or min of range) |
| `--payment-amount-max-msats` | unset | if set, sample uniformly in [min, max] per tx |
| `--target-denomination-sets` | `2` | wallet's tier-inventory target (matches balancer default) |
| `--bootstrap-amount-msats` | `4194304` | per-worker funding pulled via the bank |
| `--data-dir` | (memory) | persistent DBs across sweep steps within one federation |
| `--report-json` | stdout | write JSON report to a file |
| `--no-warmup` | off | skip the priming tx |

## Reading the report

Top-level JSON fields:

- `target_tps`, `achieved_tps`, `duration_secs`, `submitted`, `completed`,
  `errors`, `backed_up` — overall sanity.
- `accepted_latency_ms`, `finalized_latency_ms` — `{n, min, p50, p90, p95,
  p99, max, avg}` over all settled txs.
- `user_outputs_per_tx`, `change_outputs_per_tx`, `total_outputs_per_tx` —
  per-tx note count distributions.
- `payment_msats_per_tx` — what payments were actually drawn (handy when
  using random ranges).
- `per_second` — submitted / completed / in_flight / errors / p50 + p95
  finalized latency for each second of the run.

`backed_up` is `true` when achieved < 85 % of target *or* p95 > 3 × p50.
Note the latter is unreliable for `n < ~100` samples (one outlier can
trip it).

## Why a worker pool

A single Fedimint client's state machines can't survive concurrent
in-flight wallet writes — `db.autocommit` panics after 100 `WriteConflict`
retries when many ops race. The bench used to share one client across many
in-flight txs and would die within seconds at modest TPS. The fix is one
DB per worker, with strict sequential submission inside each worker. Total
TPS scales with worker count.

The first worker is also the **bank**: it pulls one combined chunk from
`fedimint-cli spend` and redistributes to the other workers via OOB notes,
so the federation's CLI bitcoin allowance isn't depleted by N independent
spends.

## Known limitations

- Input count per tx isn't reported (would require either a wallet-state
  snapshot diff around each autocommit or exposing the built `Transaction`
  from `finalize_and_submit_transaction_dbtx`, which is currently private).
- The bench shares the host with the federation peers and gateways. For
  publishable numbers, isolate the federation (separate machines, or
  `taskset` / cgroups) and pin the bench off the federation's cores.
- Long-tail outliers near consensus session boundaries (~4 s in regtest)
  are an AlephBFT property, not bench overhead.
