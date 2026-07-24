#!/usr/bin/env bash
# Real-chain (devimint + anvil) end-to-end test for the USDT-on-EVM module.
#
# NOT part of the default CI lane (`test-ci-all.sh`/`backend-test.sh`):
# enabling the usdt module makes every guardian pay a real cggmp21 DKG
# (~100s+) at startup, which would slow down the default suite. The gating
# Phase 5 acceptance test is the hermetic `deposit_becomes_claimable_usdt_ecash`
# in `modules/fedimint-usdt-tests/tests/tests.rs` (`MockEvmRpc`-backed, runs in
# default CI). This script is an opt-in lane for a real nix devshell/CI job --
# see the `test-usdt-e2e` justfile recipe.

set -euo pipefail
export RUST_LOG="${RUST_LOG:-info}"

source scripts/_common.sh
build_workspace
add_target_dir_to_path
make_fm_test_marker

usdt-e2e-test "$@"
