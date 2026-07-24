// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

// This contract is compiled OFFLINE with `forge build` and its creation
// bytecode + ABI are committed as a fixture at
// `modules/fedimint-usdt-tests/tests/fixtures/mock_aggregator_v3.json`. Tests
// deploy that committed bytecode directly to an anvil instance and do NOT
// invoke solc/forge at test time. This file is kept for provenance/readability
// only.
//
// To regenerate the fixture:
//   1. Copy this file into `src/MockAggregatorV3.sol` of a scratch foundry
//      project (`forge init --no-git <dir>` or a minimal `foundry.toml` +
//      `src/`).
//   2. Run `forge build` (last verified with forge/solc 1.4.4-dev / 0.8.30).
//   3. Read `out/MockAggregatorV3.sol/MockAggregatorV3.json` and extract
//      `.bytecode.object` (the creation bytecode) and `.abi` into
//      `modules/fedimint-usdt-tests/tests/fixtures/mock_aggregator_v3.json` as
//      `{"abi": [...], "bytecode": "0x..."}`.
//   4. Sanity-check by deploying the extracted bytecode (with constructor args
//      `(int256 answer_, uint8 decimals_)` ABI-encoded and appended) to a
//      throwaway anvil instance with `cast send --create <bytecode+args>` and
//      calling `decimals()`/`latestRoundData()`.

/// @title MockAggregatorV3
/// @notice A minimal stand-in for Chainlink's `AggregatorV3Interface`
/// (`decimals()` + `latestRoundData()`), used by
/// `fedimint-usdt-tests/tests/withdraw_e2e.rs` to prove
/// `AlloyEvmRpc::get_fee_estimate` reads a real on-chain feed (rather than the
/// static `$3000` fallback) end-to-end against `anvil`. NOT a production
/// oracle: `latestRoundData()` always reports the constructor-fixed `answer`
/// as of the block it was deployed in, with a single always-complete round.
contract MockAggregatorV3 {
    int256 private _answer;
    uint8 private _decimals;
    uint256 private _updatedAt;
    uint80 private _roundId;

    constructor(int256 answer_, uint8 decimals_) {
        _answer = answer_;
        _decimals = decimals_;
        _updatedAt = block.timestamp;
        _roundId = 1;
    }

    function decimals() external view returns (uint8) {
        return _decimals;
    }

    function latestRoundData()
        external
        view
        returns (uint80 roundId, int256 answer, uint256 startedAt, uint256 updatedAt, uint80 answeredInRound)
    {
        return (_roundId, _answer, _updatedAt, _updatedAt, _roundId);
    }
}
