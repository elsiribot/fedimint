#!/usr/bin/env bash
# Smoke test for the `anvil` EVM devnet devimint daemon: starts anvil
# standalone and checks it responds over JSON-RPC as expected.

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info}"

source scripts/_common.sh
build_workspace
add_target_dir_to_path
make_fm_test_marker

devimint anvil-smoke-test
