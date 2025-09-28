// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.24;

/**
 * Enhanced Dex223 — ERC223 Token + Advanced Merkle‑based Rewards Distributor
 * 
 * Copyright (C) 2025 Dex223
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 *
 * Improvements implemented:
 *  - Minimum claim amounts to prevent dust attacks
 *  - Time delays between claims (cooldown period)
 *  - Multi-token support with validation
 *  - Epoch-specific funding tracking
 *  - Recovery mechanism for wrong token deposits
 *
 * Overview
 *  - Dex223Token: ERC223 + (ERC20‑style allowances) with AccessControl, Pausable, Minting, and EIP‑165‑like recipient hook checks.
 *  - Dex223RewardsEnhanced: Advanced Merkle proof claims with anti-Sybil mechanisms and multi-token support.
 */

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @notice Minimal ERC223 interfaces
interface IERC223 is IERC20 {
    function transfer(address to, uint256 value, bytes calldata data) external returns (bool);
    function name() external view returns (string memory);
    function symbol() external view returns (string memory);
    function decimals() external view returns (uint8);
    /// @dev ERC223 Transfer event variant with data payload
    event TransferData(address indexed from, address indexed to, uint256 value, bytes data);
}

interface IERC223Recipient {
    function tokenFallback(address from, uint256 value, bytes calldata data) external;
}

/**
 * @title Dex223Token (ERC223 + allowances)
 * @dev Implements ERC223 semantics and ERC20‑style approvals. Uses AccessControl for admin/minter roles.
 */
contract Dex223Token is IERC223, AccessControl, Pausable {
    // --- Roles ---
    bytes32 public constant ADMIN_ROLE = DEFAULT_ADMIN_ROLE; // can pause, set metadata, grant roles
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    // --- Storage ---
    string private _name;
    string private _symbol;
    uint8 private immutable _decimals;
    uint256 private _totalSupply;

    mapping(address => uint256) private _balanceOf;
    mapping(address => mapping(address => uint256)) private _allowance;

    // --- Events --- (ERC20 Transfer/Approval already in interface; ERC223 variant declared in IERC223)

    constructor(string memory name_, string memory symbol_, uint8 decimals_, address admin_) {
        _name = name_;
        _symbol = symbol_;
        _decimals = decimals_;
        _grantRole(ADMIN_ROLE, admin_);
        _grantRole(MINTER_ROLE, admin_);
    }

    // --- Views ---
    function name() external view override returns (string memory) { return _name; }
    function symbol() external view override returns (string memory) { return _symbol; }
    function decimals() external view override returns (uint8) { return _decimals; }
    function totalSupply() external view override returns (uint256) { return _totalSupply; }
    function balanceOf(address account) public view override returns (uint256) { return _balanceOf[account]; }
    function allowance(address owner, address spender) external view override returns (uint256) { return _allowance[owner][spender]; }

    // --- Admin ---
    function pause() external onlyRole(ADMIN_ROLE) { _pause(); }
    function unpause() external onlyRole(ADMIN_ROLE) { _unpause(); }
    function setNameSymbol(string calldata name_, string calldata symbol_) external onlyRole(ADMIN_ROLE) {
        _name = name_;
        _symbol = symbol_;
    }

    // --- Internal helpers ---
    function _isContract(address account) internal view returns (bool) {
        return account.code.length > 0;
    }

    // --- ERC20/223 transfers ---
    function transfer(address to, uint256 value) external override whenNotPaused returns (bool) {
        _transfer(msg.sender, to, value, "");
        return true;
    }

    function transfer(address to, uint256 value, bytes calldata data) external override whenNotPaused returns (bool) {
        _transfer(msg.sender, to, value, data);
        return true;
    }

    function approve(address spender, uint256 amount) external override whenNotPaused returns (bool) {
        _allowance[msg.sender][spender] = amount;
        emit Approval(msg.sender, spender, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 value) external override whenNotPaused returns (bool) {
        uint256 cur = _allowance[from][msg.sender];
        require(cur >= value, "ALLOWANCE");
        unchecked { _allowance[from][msg.sender] = cur - value; }
        _transfer(from, to, value, "");
        return true;
    }

    function increaseAllowance(address spender, uint256 added) external whenNotPaused returns (bool) {
        uint256 newAllow = _allowance[msg.sender][spender] + added;
        _allowance[msg.sender][spender] = newAllow;
        emit Approval(msg.sender, spender, newAllow);
        return true;
    }

    function decreaseAllowance(address spender, uint256 subtracted) external whenNotPaused returns (bool) {
        uint256 cur = _allowance[msg.sender][spender];
        require(cur >= subtracted, "ALLOWANCE");
        unchecked { cur -= subtracted; }
        _allowance[msg.sender][spender] = cur;
        emit Approval(msg.sender, spender, cur);
        return true;
    }

    // --- Mint/Burn ---
    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) whenNotPaused {
        require(to != address(0), "ZERO");
        _totalSupply += amount;
        _balanceOf[to] += amount;
        emit Transfer(address(0), to, amount);
        emit TransferData(address(0), to, amount, "");
        if (_isContract(to)) {
            IERC223Recipient(to).tokenFallback(msg.sender, amount, "");
        }
    }

    function burn(uint256 amount) external whenNotPaused {
        uint256 bal = _balanceOf[msg.sender];
        require(bal >= amount, "BALANCE");
        unchecked { _balanceOf[msg.sender] = bal - amount; }
        _totalSupply -= amount;
        emit Transfer(msg.sender, address(0), amount);
        emit TransferData(msg.sender, address(0), amount, "");
    }

    // --- Core transfer logic ---
    function _transfer(address from, address to, uint256 value, bytes memory data) internal {
        require(to != address(0), "ZERO");
        require(value > 0, "ZERO_AMOUNT"); // Added zero-value protection
        uint256 bal = _balanceOf[from];
        require(bal >= value, "BALANCE");

        unchecked {
            _balanceOf[from] = bal - value;
            _balanceOf[to] += value;
        }

        // Emit both events for compatibility
        emit Transfer(from, to, value);
        emit TransferData(from, to, value, data);

        // Interactions (after effects): if recipient is a contract, notify
        if (_isContract(to)) {
            IERC223Recipient(to).tokenFallback(from, value, data);
        }
    }
}

/**
 * @title Dex223RewardsEnhanced (Advanced ERC223 Merkle distributor with anti-Sybil features)
 *
 * Enhanced features:
 *  - Minimum claim amounts to prevent dust attacks
 *  - Cooldown periods between claims
 *  - Multi-token support with validation
 *  - Epoch-specific funding tracking
 *  - Token recovery mechanism
 *
 * Claim flow
 *  - Admin configures epoch with token address and merkle root
 *  - Admin funds the epoch with specified token amount
 *  - Users claim after cooldown period with minimum amount checks
 *  - Contract validates token, amount, and timing before distribution
 */
contract Dex223RewardsEnhanced is IERC223Recipient, AccessControl, Pausable, ReentrancyGuard {
    // --- Roles ---
    bytes32 public constant ADMIN_ROLE = DEFAULT_ADMIN_ROLE;
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");

    // --- Structs ---
    struct EpochConfig {
        bytes32 merkleRoot;
        address rewardToken;      // Token address for this epoch
        uint256 totalAllocated;   // Total amount allocated for distribution
        uint256 totalFunded;      // Actual amount funded
        uint256 totalClaimed;     // Amount already claimed
        uint256 startTime;        // When claiming starts
        uint256 endTime;          // When claiming ends (0 = no end)
        bool isActive;            // Whether epoch is active
    }

    struct ClaimRecord {
        uint256 amount;           // Amount claimed
        uint256 timestamp;        // When it was claimed
        address referrer;         // Who referred them
    }

    // --- Config ---
    uint16 public referralBps = 1000;                    // 10.00% default (basis points)
    uint256 public minimumClaimAmount = 1e18;            // Minimum claim (1 token with 18 decimals)
    uint256 public claimCooldownPeriod = 1 days;         // Time between claims for same account
    
    // --- Storage ---
    mapping(uint256 => EpochConfig) public epochs;
    mapping(address => bool) public supportedTokens;     // Whitelist of supported reward tokens
    
    // User claim tracking
    mapping(uint256 => mapping(address => ClaimRecord)) public claimRecords;
    mapping(address => uint256) public lastClaimTime;    // Global last claim time per user
    
    // Token recovery tracking
    mapping(address => uint256) public unknownTokenBalance;  // For wrong token deposits

    // --- Events ---
    event EpochCreated(uint256 indexed epoch, address indexed token, bytes32 root, uint256 startTime, uint256 endTime);
    event EpochFunded(uint256 indexed epoch, address indexed from, uint256 amount);
    event TokenWhitelisted(address indexed token, bool status);
    event MinimumClaimUpdated(uint256 amount);
    event CooldownUpdated(uint256 period);
    event ReferralBpsUpdated(uint16 bps);
    event Claimed(
        uint256 indexed epoch, 
        address indexed account, 
        uint256 amount, 
        address indexed referrer, 
        uint256 refAmount,
        address token
    );
    event TokensRecovered(address indexed token, address indexed to, uint256 amount);
    event UnknownTokenReceived(address indexed token, address indexed from, uint256 amount);

    constructor(address admin_) {
        _grantRole(ADMIN_ROLE, admin_);
        _grantRole(OPERATOR_ROLE, admin_);
    }

    // --- Admin: Token Management ---
    
    /**
     * @notice Whitelist/delist a token for rewards
     */
    function setTokenSupport(address token, bool supported) external onlyRole(ADMIN_ROLE) {
        require(token != address(0), "ZERO_TOKEN");
        supportedTokens[token] = supported;
        emit TokenWhitelisted(token, supported);
    }

    /**
     * @notice Create or update an epoch configuration
     * @param epoch Epoch ID
     * @param token Reward token address (must be whitelisted)
     * @param root Merkle root for this epoch
     * @param totalAllocated Total tokens allocated for distribution
     * @param startTime When claiming can begin (0 = immediately)
     * @param endTime When claiming ends (0 = never)
     */
    function configureEpoch(
        uint256 epoch,
        address token,
        bytes32 root,
        uint256 totalAllocated,
        uint256 startTime,
        uint256 endTime
    ) external onlyRole(OPERATOR_ROLE) {
        require(supportedTokens[token], "UNSUPPORTED_TOKEN");
        require(root != bytes32(0), "INVALID_ROOT");
        require(totalAllocated > 0, "ZERO_ALLOCATION");
        require(endTime == 0 || endTime > startTime, "INVALID_TIME");
        
        EpochConfig storage cfg = epochs[epoch];
        
        // Prevent changing token after funding
        if (cfg.totalFunded > 0) {
            require(cfg.rewardToken == token, "TOKEN_CHANGE");
        }
        
        cfg.merkleRoot = root;
        cfg.rewardToken = token;
        cfg.totalAllocated = totalAllocated;
        cfg.startTime = startTime;
        cfg.endTime = endTime;
        cfg.isActive = true;
        
        emit EpochCreated(epoch, token, root, startTime, endTime);
    }

    /**
     * @notice Deactivate an epoch (emergency stop)
     */
    function deactivateEpoch(uint256 epoch) external onlyRole(ADMIN_ROLE) {
        epochs[epoch].isActive = false;
    }

    // --- Admin: Parameter Management ---
    
    function setMinimumClaimAmount(uint256 amount) external onlyRole(ADMIN_ROLE) {
        minimumClaimAmount = amount;
        emit MinimumClaimUpdated(amount);
    }
    
    function setClaimCooldown(uint256 period) external onlyRole(ADMIN_ROLE) {
        require(period <= 30 days, "COOLDOWN_TOO_LONG");
        claimCooldownPeriod = period;
        emit CooldownUpdated(period);
    }
    
    function setReferralBps(uint16 bps) external onlyRole(ADMIN_ROLE) { 
        require(bps <= 5000, "REF_BPS"); 
        referralBps = bps; 
        emit ReferralBpsUpdated(bps); 
    }
    
    function pause() external onlyRole(ADMIN_ROLE) { _pause(); }
    function unpause() external onlyRole(ADMIN_ROLE) { _unpause(); }

    // --- Claiming ---
    
    /**
     * @notice Claim rewards for an epoch with enhanced validation
     */
    function claim(
        uint256 epoch,
        address account,
        uint256 amount,
        bytes32[] calldata proof,
        address referrer
    ) external whenNotPaused nonReentrant {
        EpochConfig storage cfg = epochs[epoch];
        
        // Validate epoch
        require(cfg.isActive, "EPOCH_INACTIVE");
        require(cfg.merkleRoot != bytes32(0), "EPOCH_NOT_SET");
        require(block.timestamp >= cfg.startTime, "NOT_STARTED");
        require(cfg.endTime == 0 || block.timestamp <= cfg.endTime, "ENDED");
        
        // Check if already claimed for this epoch
        require(claimRecords[epoch][account].amount == 0, "ALREADY_CLAIMED");
        
        // Anti-Sybil: Check minimum amount
        require(amount >= minimumClaimAmount, "BELOW_MINIMUM");
        
        // Anti-Sybil: Check cooldown
        if (lastClaimTime[account] > 0) {
            require(
                block.timestamp >= lastClaimTime[account] + claimCooldownPeriod,
                "COOLDOWN"
            );
        }
        
        // Verify Merkle proof
        bytes32 leaf = keccak256(abi.encodePacked(account, amount));
        require(MerkleProof.verifyCalldata(proof, cfg.merkleRoot, leaf), "INVALID_PROOF");
        
        // Calculate amounts
        uint256 refAmount = 0;
        if (referrer != address(0) && referrer != account && referralBps > 0) {
            refAmount = (amount * referralBps) / 10_000;
        }
        uint256 userAmount = amount - refAmount;
        
        // Check funding availability
        require(cfg.totalClaimed + amount <= cfg.totalFunded, "INSUFFICIENT_FUNDING");
        require(cfg.totalClaimed + amount <= cfg.totalAllocated, "EXCEEDS_ALLOCATION");
        
        // Update state
        cfg.totalClaimed += amount;
        claimRecords[epoch][account] = ClaimRecord({
            amount: amount,
            timestamp: block.timestamp,
            referrer: referrer
        });
        lastClaimTime[account] = block.timestamp;
        
        // Prepare metadata
        bytes memory dataUser = abi.encode(epoch, uint8(1), referrer);
        bytes memory dataRef = abi.encode(epoch, uint8(2), account);
        
        // Execute transfers
        IERC223(cfg.rewardToken).transfer(account, userAmount, dataUser);
        if (refAmount > 0) {
            IERC223(cfg.rewardToken).transfer(referrer, refAmount, dataRef);
        }
        
        emit Claimed(epoch, account, amount, referrer, refAmount, cfg.rewardToken);
    }

    // --- Funding ---
    
    /**
     * @notice ERC223 receiver - handles epoch funding and tracks unknown tokens
     */
    function tokenFallback(address from, uint256 value, bytes calldata data) external override {
        // Check if token is supported
        if (!supportedTokens[msg.sender]) {
            // Track unknown token for recovery
            unknownTokenBalance[msg.sender] += value;
            emit UnknownTokenReceived(msg.sender, from, value);
            return;
        }
        
        // Decode epoch from data if provided
        uint256 epochId = 0;
        if (data.length >= 32) {
            epochId = abi.decode(data, (uint256));
        }
        
        // If epoch specified, fund it specifically
        if (epochId > 0 && epochs[epochId].rewardToken == msg.sender) {
            epochs[epochId].totalFunded += value;
            emit EpochFunded(epochId, from, value);
        } else {
            // Generic funding - admin must assign to epoch later
            unknownTokenBalance[msg.sender] += value;
            emit UnknownTokenReceived(msg.sender, from, value);
        }
    }
    
    /**
     * @notice Manually fund an epoch from contract balance
     */
    function fundEpoch(uint256 epoch, uint256 amount) external onlyRole(OPERATOR_ROLE) {
        EpochConfig storage cfg = epochs[epoch];
        require(cfg.rewardToken != address(0), "EPOCH_NOT_SET");
        require(unknownTokenBalance[cfg.rewardToken] >= amount, "INSUFFICIENT_BALANCE");
        
        unknownTokenBalance[cfg.rewardToken] -= amount;
        cfg.totalFunded += amount;
        
        emit EpochFunded(epoch, address(this), amount);
    }

    // --- Recovery & Views ---
    
    /**
     * @notice Recover wrongly sent tokens
     */
    function recoverTokens(address token, address to, uint256 amount) external onlyRole(ADMIN_ROLE) {
        // For unknown/unsupported tokens
        if (!supportedTokens[token]) {
            require(unknownTokenBalance[token] >= amount, "INSUFFICIENT_UNKNOWN");
            unknownTokenBalance[token] -= amount;
            IERC223(token).transfer(to, amount, "RECOVERY");
            emit TokensRecovered(token, to, amount);
            return;
        }
        
        // For supported tokens, ensure we don't touch allocated funds
        uint256 allocated = 0;
        // Note: In production, you'd want to iterate through epochs more efficiently
        for (uint256 i = 1; i <= 100; i++) { // Assuming max 100 epochs
            if (epochs[i].rewardToken == token && epochs[i].isActive) {
                uint256 remaining = epochs[i].totalFunded - epochs[i].totalClaimed;
                allocated += remaining;
            }
        }
        
        uint256 available = IERC223(token).balanceOf(address(this)) - allocated;
        require(amount <= available, "EXCEEDS_AVAILABLE");
        
        IERC223(token).transfer(to, amount, "RECOVERY");
        emit TokensRecovered(token, to, amount);
    }
    
    /**
     * @notice Check if an address has claimed for an epoch
     */
    function hasClaimed(uint256 epoch, address account) external view returns (bool) {
        return claimRecords[epoch][account].amount > 0;
    }
    
    /**
     * @notice Get detailed epoch info
     */
    function getEpochInfo(uint256 epoch) external view returns (
        bytes32 merkleRoot,
        address rewardToken,
        uint256 totalAllocated,
        uint256 totalFunded,
        uint256 totalClaimed,
        uint256 startTime,
        uint256 endTime,
        bool isActive,
        bool canClaim
    ) {
        EpochConfig storage cfg = epochs[epoch];
        return (
            cfg.merkleRoot,
            cfg.rewardToken,
            cfg.totalAllocated,
            cfg.totalFunded,
            cfg.totalClaimed,
            cfg.startTime,
            cfg.endTime,
            cfg.isActive,
            cfg.isActive && 
            block.timestamp >= cfg.startTime && 
            (cfg.endTime == 0 || block.timestamp <= cfg.endTime) &&
            cfg.totalClaimed < cfg.totalFunded
        );
    }
    
    /**
     * @notice Check if user can claim (considering cooldown)
     */
    function canUserClaim(address user) external view returns (bool) {
        if (lastClaimTime[user] == 0) return true;
        return block.timestamp >= lastClaimTime[user] + claimCooldownPeriod;
    }
    
    /**
     * @notice Get user's time until next claim
     */
    function timeUntilNextClaim(address user) external view returns (uint256) {
        if (lastClaimTime[user] == 0) return 0;
        uint256 nextClaimTime = lastClaimTime[user] + claimCooldownPeriod;
        if (block.timestamp >= nextClaimTime) return 0;
        return nextClaimTime - block.timestamp;
    }
}
