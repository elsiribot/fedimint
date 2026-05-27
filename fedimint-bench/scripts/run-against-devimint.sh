#!/usr/bin/env bash
# Run a TPS-ramp benchmark inside a freshly-spawned devimint regtest federation.
#
# Usage: fedimint-bench/scripts/run-against-devimint.sh [tps1 tps2 ...]
#
# Defaults to a small ramp covering low → high TPS so we can see where the
# federation begins to back up. Reports land in $RESULT_DIR.

set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

source scripts/_common.sh
add_target_dir_to_path
export FM_DEVIMINT_STATIC_DATA_DIR="${REPO_ROOT}/devimint/share"

# Each entry is "<tps>:<workers>". We sweep TPS and pick a worker count that
# leaves headroom over (tps × federation_round_trip).
SWEEP=("$@")
if [ "${#SWEEP[@]}" -eq 0 ]; then
  SWEEP=(1:1 2:2 5:4 10:8 20:16 40:32)
fi

DURATION_SECS="${DURATION_SECS:-20}"
# Payment amount per bench tx (msat). If PAYMENT_MAX_MSATS is also set the
# bench samples a uniform random amount in [PAYMENT_MSATS, PAYMENT_MAX_MSATS]
# per tx, otherwise it pays a fixed PAYMENT_MSATS. The mint module decomposes
# the chosen amount into tier-denominated notes via `represent_amount`, so
# any value produces realistic multi-output txs.
PAYMENT_MSATS="${PAYMENT_MSATS:-10000}"
PAYMENT_MAX_MSATS="${PAYMENT_MAX_MSATS:-1000000}"
RESULT_DIR="${RESULT_DIR:-$REPO_ROOT/target-nix/bench-results}"
mkdir -p "$RESULT_DIR"

cat > "$RESULT_DIR/inner.sh" <<'INNER'
#!/usr/bin/env bash
set -euo pipefail
echo "Federation env file:"
env | grep -E '^FM_|^RUST_' | sort

# Warm up: convert some sats into spendable e-cash by running fedimint-cli info
fedimint-cli --data-dir "$FM_CLIENT_DIR" info || true

SWEEP="$BENCH_SWEEP"
DURATION_SECS="$BENCH_DURATION"
PAYMENT_MSATS="$BENCH_PAYMENT"
PAYMENT_MAX_MSATS="${BENCH_PAYMENT_MAX:-}"
RESULT_DIR="$BENCH_RESULT_DIR"

# Persistent worker DBs let later sweep steps re-use earlier workers' wallets,
# so the devimint CLI's bitcoin allowance doesn't have to fund every step
# from scratch. The reuse is only valid WITHIN ONE devimint federation — a new
# `devimint dev-fed` brings up peers with fresh iroh node IDs / WS ports, so
# any cached client config from a previous session is stale. Wipe it.
WORKER_DIR="$RESULT_DIR/workers-db"
rm -rf "$WORKER_DIR"
mkdir -p "$WORKER_DIR"

for entry in $SWEEP; do
  tps="${entry%%:*}"
  workers="${entry##*:}"
  echo
  echo "===== Running TPS=$tps workers=$workers duration=${DURATION_SECS}s ====="
  max_arg=()
  if [ -n "$PAYMENT_MAX_MSATS" ]; then
    max_arg=(--payment-amount-max-msats "$PAYMENT_MAX_MSATS")
  fi
  fedimint-bench \
    --target-tps "$tps" \
    --workers "$workers" \
    --duration-secs "$DURATION_SECS" \
    --payment-amount-msats "$PAYMENT_MSATS" \
    "${max_arg[@]}" \
    --data-dir "$WORKER_DIR" \
    --report-json "$RESULT_DIR/report-tps-$tps.json" \
    2>&1 | tee "$RESULT_DIR/log-tps-$tps.txt"
done

echo
echo "===== All results in $RESULT_DIR ====="
ls -la "$RESULT_DIR"
INNER
chmod +x "$RESULT_DIR/inner.sh"

# devimint exec passes through the env; expose our params that way
export BENCH_SWEEP="${SWEEP[*]}"
export BENCH_DURATION="$DURATION_SECS"
export BENCH_PAYMENT="$PAYMENT_MSATS"
export BENCH_PAYMENT_MAX="$PAYMENT_MAX_MSATS"
export BENCH_RESULT_DIR="$RESULT_DIR"

DEVIMINT_DIR="${CARGO_BUILD_TARGET_DIR:-target}/devimint"
# $DEVIMINT_DIR is a symlink that devimint manages; remove if present so the
# fresh `--link-test-dir` symlink can be created cleanly.
if [ -L "$DEVIMINT_DIR" ]; then
  rm -f "$DEVIMINT_DIR"
elif [ -d "$DEVIMINT_DIR" ]; then
  rm -rf "$DEVIMINT_DIR"
fi

echo "Result dir: $RESULT_DIR"
echo "Sweep:      ${SWEEP[*]}"

env RUST_LOG="${RUST_LOG:-info,jsonrpsee-client=off}" \
  devimint --link-test-dir "$DEVIMINT_DIR" dev-fed \
    --exec bash -c "$RESULT_DIR/inner.sh"
