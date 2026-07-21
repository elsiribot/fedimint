#!/usr/bin/env bash
# Smoke test for the module generation dashboard: propose a mint module via
# the ui, approve from every guardian dashboard and wait for the DKG.
#
# Usage:
#   cargo build --bin fedimintd --bin devimint --bin gatewayd --bin gateway-cli \
#     --bin fedimint-cli --bin fedimint-recurringd --bin fedimint-recurringdv2
#   PATH="$PWD/target-nix/debug:$PATH" FM_FEDERATIONS_BASE_PORT=2000 \
#     devimint dev-fed --exec bash scripts/dev/config-gen-ui-smoke.sh
set -euo pipefail

cookies() { echo "/tmp/ui-smoke-cookies-$1"; }
port() { echo $((2002 + $1 * 4)); }

for i in 0 1 2 3; do
  curl -sf -c "$(cookies "$i")" -X POST -d "password=pass" "http://127.0.0.1:$(port "$i")/login" >/dev/null
done

curl -sf -b "$(cookies 0)" "http://127.0.0.1:$(port 0)/" | grep -q "Module Generation"
echo "SMOKE: dashboard renders module generation section"

curl -sf -b "$(cookies 0)" -X POST -d "name=US Dollar&ticker=USD" \
  "http://127.0.0.1:$(port 0)/assets/register" >/dev/null
for _ in $(seq 30); do
  if curl -sf -b "$(cookies 0)" "http://127.0.0.1:$(port 0)/" | grep -q ">USD<"; then
    break
  fi
  sleep 2
done
curl -sf -b "$(cookies 0)" "http://127.0.0.1:$(port 0)/" | grep -q ">USD<"
echo "SMOKE: asset registered and visible"

curl -sf -b "$(cookies 0)" "http://127.0.0.1:$(port 0)/config-gen/propose-form?kind=mint" \
  | grep -q "param_amount_unit"
curl -sf -b "$(cookies 0)" -X POST -d "kind=mint&param_amount_unit=1" \
  "http://127.0.0.1:$(port 0)/config-gen/propose" >/dev/null
echo "SMOKE: proposed mint with amount_unit param"

for _ in $(seq 30); do
  if curl -sf -b "$(cookies 0)" "http://127.0.0.1:$(port 0)/" | grep -q "Proposed</span>"; then
    break
  fi
  sleep 2
done
curl -sf -b "$(cookies 0)" "http://127.0.0.1:$(port 0)/" | grep -q "Proposed</span>"
echo "SMOKE: proposal visible via dashboard"

for i in 1 2 3; do
  for _ in $(seq 30); do
    if curl -sf -b "$(cookies "$i")" "http://127.0.0.1:$(port "$i")/" | grep -q "Proposed</span>"; then
      break
    fi
    sleep 2
  done
  status=$(curl -s -o /dev/null -w "%{http_code} -> %{redirect_url}" -b "$(cookies "$i")" -X POST -d "generation_id=0" "http://127.0.0.1:$(port "$i")/config-gen/approve")
  echo "SMOKE: approve on peer $i: $status"
done
echo "SMOKE: all guardians approved via dashboard"

ready=0
for _ in $(seq 90); do
  if curl -sf -b "$(cookies 0)" "http://127.0.0.1:$(port 0)/" | grep -q "Ready for activation"; then
    echo "SMOKE: DKG completed, generation ready for activation"
    ready=1
    break
  fi
  sleep 2
done

if [ "$ready" = 1 ]; then
  # Hot activation: the module goes live without a daemon restart. The
  # dashboard is respawned in-process for a moment, so tolerate brief
  # unreachability but fail if it stays down (a real restart gap).
  curl -s -o /dev/null -b "$(cookies 0)" -X POST -d "generation_id=0" \
    "http://127.0.0.1:$(port 0)/config-gen/activate"
  echo "SMOKE: activation requested via dashboard"

  consecutive_failures=0
  for _ in $(seq 120); do
    page=$(curl -s -m 2 -b "$(cookies 0)" "http://127.0.0.1:$(port 0)/") || true
    if [ -z "$page" ]; then
      consecutive_failures=$((consecutive_failures + 1))
      if [ "$consecutive_failures" -gt 5 ]; then
        echo "SMOKE: dashboard unreachable for >5s during activation, daemon restarted?"
        exit 1
      fi
    else
      consecutive_failures=0
      if echo "$page" | grep -q 'text-bg-success">Active'; then
        echo "SMOKE: module hot activated, dashboard stayed up throughout"
        exit 0
      fi
    fi
    sleep 1
  done

  echo "SMOKE: TIMEOUT waiting for hot activation"
  exit 1
fi

echo "SMOKE: TIMEOUT waiting for generation to complete"
for i in 0 1 2 3; do
  echo "SMOKE: peer $i state:"
  curl -s -b "$(cookies "$i")" "http://127.0.0.1:$(port "$i")/" \
    | grep -oE 'text-bg-[a-z]+">[A-Za-z ]+</span>|<td>[0-9]+/[0-9]+ [a-z]+</td>' | head -4
  echo "SMOKE: peer $i log lines:"
  grep -aE "ConfigGen|Unable to submit|Failed to (propose|approve|activate|abort)|Aborting generation|Running module config generation" \
    "${FM_LOGS_DIR}/fedimintd-default-$i.log" 2>/dev/null | tail -15
done
exit 1
