// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// This contract is compiled OFFLINE with `forge build` and its creation
// bytecode + ABI are committed as a fixture at
// `modules/fedimint-usdt-tests/tests/fixtures/test_usdt.json`. Tests deploy
// that committed bytecode directly to an anvil instance and do NOT invoke
// solc/forge at test time. This file is kept for provenance/readability only.
//
// To regenerate the fixture:
//   1. Copy this file into `src/TestUsdt.sol` of a scratch foundry project
//      (`forge init --no-git <dir>` or a minimal `foundry.toml` + `src/`).
//   2. Run `forge build` (last verified with forge/solc 0.8.33).
//   3. Read `out/TestUsdt.sol/TestUsdt.json` and extract `.bytecode.object`
//      (the creation bytecode) and `.abi` into
//      `modules/fedimint-usdt-tests/tests/fixtures/test_usdt.json` as
//      `{"abi": [...], "bytecode": "0x..."}`.
//   4. Sanity-check by deploying the extracted bytecode to a throwaway
//      anvil instance with `cast send --create <bytecode>` and calling
//      `decimals()` (expect 6).

/// @title TestUsdt
/// @notice Minimal, self-contained ERC-20-like token used ONLY as a
/// deterministic test fixture for the fedimint-usdt-tests EVM harness.
/// It intentionally mimics USDT's 6 decimals and exposes a public `mint`
/// so tests can seed arbitrary balances without a faucet contract.
/// This is NOT a production token and has no access control on `mint`.
contract TestUsdt {
    string public constant name = "Test USDT";
    string public constant symbol = "tUSDT";
    uint8 public constant decimals = 6;

    uint256 public totalSupply;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);

    function mint(address to, uint256 amount) public {
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }

    function transfer(address to, uint256 amount) public returns (bool) {
        require(balanceOf[msg.sender] >= amount, "insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function approve(address spender, uint256 amount) public returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        require(balanceOf[from] >= amount, "insufficient balance");
        require(allowance[from][msg.sender] >= amount, "insufficient allowance");
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }
}
