// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// This contract is compiled OFFLINE with `forge build` and its creation
// bytecode + ABI are committed as a fixture at
// `modules/fedimint-usdt-tests/tests/fixtures/nonstandard_usdt.json`. Tests
// deploy that committed bytecode directly to an anvil instance and do NOT
// invoke solc/forge at test time. This file is kept for provenance/readability
// only.
//
// To regenerate the fixture:
//   1. Copy this file into `src/NonStandardUsdt.sol` of a scratch foundry
//      project (`forge init --no-git <dir>` or a minimal `foundry.toml` +
//      `src/`).
//   2. Run `forge build` (last verified with forge/solc 0.8.33).
//   3. Read `out/NonStandardUsdt.sol/NonStandardUsdt.json` and extract
//      `.bytecode.object` (the creation bytecode) and `.abi` into
//      `modules/fedimint-usdt-tests/tests/fixtures/nonstandard_usdt.json` as
//      `{"abi": [...], "bytecode": "0x..."}`.
//   4. Sanity-check by deploying the extracted bytecode to a throwaway anvil
//      instance with `cast send --create <bytecode>` and calling `decimals()`
//      (expect 6).

/// @title NonStandardUsdt
/// @notice A deterministic test fixture that faithfully reproduces the
/// NON-STANDARD quirks of mainnet Tether (`TetherToken`,
/// `0xdAC17F958D2ee523a2206206994597C13D831ec7`, originally compiled with
/// solc 0.4.x) that matter for this module's ERC-4337 sweep/withdrawal path,
/// while staying a small, auditable, modern-solc contract. It is NOT a
/// production token and has no access control on `mint` (mirroring `TestUsdt`).
///
/// The quirks reproduced, and why they matter here:
///
/// 1. **`transfer`/`transferFrom` return NOTHING** (no `bool`). This is the
///    single most important divergence from the ERC-20 standard: the real
///    TetherToken's `transfer(address,uint256)`/`transferFrom(...)` are
///    declared `public` with no return value (its old Solidity `BasicToken`/
///    `StandardToken` base). Any caller that ABI-decodes a `bool` return from
///    these will revert against real USDT. Our sweep/withdrawal path issues
///    these via `SimpleAccount.execute`/`executeBatch`, which do a low-level
///    call and check only call-success (they never ABI-decode a return), so
///    the void return SHOULD be handled -- this fixture exists to PROVE it.
///    Note the 4-byte function SELECTOR is identical regardless of return
///    type (selectors are computed from the signature's parameter types only,
///    ignoring returns), so `transfer(address,uint256)` still selects the same
///    slot; what differs is that the runtime pushes no return data.
///
/// 2. **Transfer fee mechanism** (`basisPointsRate` + `maximumFee`): a fee is
///    deducted from the transferred `_value`, the recipient receives
///    `_value - fee`, and the remainder accrues to `owner`. On mainnet both
///    parameters are 0 (so USDT behaves like a plain transfer today), but the
///    mechanism exists on-chain and could be re-enabled, so we include it with
///    an `onlyOwner` setter and a 0 default.
///
/// 3. **6 decimals**, matching real USDT and this module's `USDT_UNIT`.
///
/// 4. (Faithfulness extras, cheap and read-only so they don't complicate the
///    sweep path) `deprecated`/`upgradedAddress` upgrade-indirection fields
///    and `getBlackListStatus`/`isBlackListed`. These are exposed for shape
///    fidelity but are inert here (`deprecated == false`, nobody blacklisted),
///    so they never affect the transfer path this fixture is testing.
contract NonStandardUsdt {
    // `constant` so they occupy NO storage slots -- this places `balanceOf` on
    // storage slot 2 below, matching mainnet USDT (TetherToken) and
    // `fedimint_usdt_common::USDT_BALANCES_SLOT`. The deposit-by-proof path
    // reads the balances mapping by that RAW slot (via `eth_getProof`).
    string public constant name = "Tether USD";
    string public constant symbol = "USDT";
    uint8 public constant decimals = 6;

    uint256 public totalSupply;

    // Padding so `balanceOf` lands on storage slot 2 (see above).
    uint256 private _slot1Reserved;

    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    address public owner;

    // --- Quirk 2: the mainnet fee mechanism (default 0 == plain transfer). ---
    uint256 public basisPointsRate = 0;
    uint256 public maximumFee = 0;
    /// Matches the real TetherToken's `MAX_UINT` guard on `setParams`: the fee
    /// rate is capped so a misconfiguration can't confiscate arbitrary value.
    uint256 public constant MAX_SETTABLE_BASIS_POINTS = 20; // 0.2%
    uint256 public constant MAX_SETTABLE_FEE = 50; // in whole token units

    // --- Quirk 4: inert upgrade-indirection + blacklist shape fidelity. ---
    bool public deprecated = false;
    address public upgradedAddress = address(0);
    mapping(address => bool) public isBlackListed;

    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    event Params(uint256 feeBasisPoints, uint256 maxFee);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    /// No access control (test fixture only): seeds arbitrary balances so tests
    /// can fund holders without a faucet, mirroring `TestUsdt.mint`.
    function mint(address to, uint256 amount) public {
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }

    /// Quirk 2: set the fee parameters (owner-only, capped like mainnet). The
    /// stored `maximumFee` is scaled by `10**decimals`, matching the real
    /// TetherToken's `maximumFee = newMaxFee.mul(10**decimals)`.
    function setParams(uint256 newBasisPoints, uint256 newMaxFee) public onlyOwner {
        require(newBasisPoints < MAX_SETTABLE_BASIS_POINTS, "basis points too high");
        require(newMaxFee < MAX_SETTABLE_FEE, "max fee too high");
        basisPointsRate = newBasisPoints;
        maximumFee = newMaxFee * (10 ** uint256(decimals));
        emit Params(basisPointsRate, maximumFee);
    }

    /// Computes the fee the real TetherToken would charge on a `_value`
    /// transfer: `_value * basisPointsRate / 10000`, capped at `maximumFee`.
    function _fee(uint256 _value) internal view returns (uint256) {
        uint256 fee = (_value * basisPointsRate) / 10000;
        if (fee > maximumFee) {
            fee = maximumFee;
        }
        return fee;
    }

    /// QUIRK 1: NO return value. Faithful to mainnet TetherToken's
    /// `transfer(address,uint256)`, plus the Quirk-2 fee split (recipient gets
    /// `_value - fee`, `owner` gets `fee`).
    function transfer(address _to, uint256 _value) public {
        require(balanceOf[msg.sender] >= _value, "insufficient balance");
        uint256 fee = _fee(_value);
        uint256 sendAmount = _value - fee;
        balanceOf[msg.sender] -= _value;
        balanceOf[_to] += sendAmount;
        if (fee > 0) {
            balanceOf[owner] += fee;
            emit Transfer(msg.sender, owner, fee);
        }
        emit Transfer(msg.sender, _to, sendAmount);
    }

    /// Standard: `approve` DOES return `bool` on the real TetherToken -- only
    /// `transfer`/`transferFrom` are void. Kept faithful.
    function approve(address spender, uint256 amount) public returns (bool) {
        allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    /// QUIRK 1: NO return value. Faithful to mainnet TetherToken's
    /// `transferFrom(address,address,uint256)`, plus the Quirk-2 fee split.
    function transferFrom(address _from, address _to, uint256 _value) public {
        require(balanceOf[_from] >= _value, "insufficient balance");
        require(allowance[_from][msg.sender] >= _value, "insufficient allowance");
        allowance[_from][msg.sender] -= _value;
        uint256 fee = _fee(_value);
        uint256 sendAmount = _value - fee;
        balanceOf[_from] -= _value;
        balanceOf[_to] += sendAmount;
        if (fee > 0) {
            balanceOf[owner] += fee;
            emit Transfer(_from, owner, fee);
        }
        emit Transfer(_from, _to, sendAmount);
    }

    /// Quirk 4: inert blacklist getter, present only for shape fidelity.
    function getBlackListStatus(address _maker) external view returns (bool) {
        return isBlackListed[_maker];
    }
}
