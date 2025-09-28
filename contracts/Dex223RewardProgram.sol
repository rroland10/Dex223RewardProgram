// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.24;

/**
 * @title D223 Merkle Distributor
 * @notice Payouts per-epoch & per-pool from a Merkle tree. Token-agnostic (USDT per chain recommended).
 *         Leaves MUST be constructed as:
 *           keccak256(abi.encodePacked(block.chainid, epoch, pool, account, token, amount))
 *         where:
 *           - epoch: uint48
 *           - pool:  uint8    (0=Trading, 1=Social, 2=Referral)
 *           - account: address
 *           - token: address  (ERC20 to transfer)
 *           - amount: uint256 (token units; off-chain handles USD normalization/decimals)
 */

import "@openzeppelin/contracts/access/Ownable2Step.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

contract MerkleDistributor is Ownable2Step, ReentrancyGuard {
    using SafeERC20 for IERC20;

    constructor(address initialOwner) Ownable(initialOwner) {}

    enum Pool { Trading, Social, Referral }

    struct RootConfig {
        bytes32 merkleRoot;
        address token;      // payout token for this (epoch, pool)
        string  epochCid;   // IPFS CID for the public epoch report
        bool    active;     // set true when committed
    }

    // epoch => pool => root config
    mapping(uint48 => mapping(uint8 => RootConfig)) public roots;

    // claimed[epoch][pool][account] => true
    mapping(uint48 => mapping(uint8 => mapping(address => bool))) public claimed;

    event RootSet(uint48 indexed epoch, uint8 indexed pool, bytes32 merkleRoot, address token, string epochCid);
    event Claimed(uint48 indexed epoch, uint8 indexed pool, address indexed account, address token, uint256 amount, address to);

    // ---------------- Owner (RootManager) APIs ----------------

    /// @notice One-time set of a Merkle root for an epoch+pool. Owner is expected to be RootManager.
    function setRoot(
        uint48 epoch,
        uint8 pool,
        bytes32 merkleRoot,
        address token,
        string calldata epochCid
    ) external onlyOwner {
        require(merkleRoot != bytes32(0), "root=0");
        require(token != address(0), "token=0");
        RootConfig storage rc = roots[epoch][pool];
        require(rc.merkleRoot == bytes32(0), "root exists");
        rc.merkleRoot = merkleRoot;
        rc.token = token;
        rc.epochCid = epochCid;
        rc.active = true;
        emit RootSet(epoch, pool, merkleRoot, token, epochCid);
    }

    /// @notice Emergency upgrade ONLY if previous root is clearly invalidated. Use with caution.
    function emergencyUpgradeRoot(
        uint48 epoch,
        uint8 pool,
        bytes32 newRoot,
        string calldata newCid
    ) external onlyOwner {
        require(newRoot != bytes32(0), "new root=0");
        RootConfig storage rc = roots[epoch][pool];
        require(rc.merkleRoot != bytes32(0), "no root");
        rc.merkleRoot = newRoot;
        rc.epochCid = newCid;
        emit RootSet(epoch, pool, newRoot, rc.token, newCid);
    }

    // ---------------- User APIs ----------------

    function isClaimed(uint48 epoch, uint8 pool, address account) external view returns (bool) {
        return claimed[epoch][pool][account];
    }

    /// @notice Claim to msg.sender.
    function claim(
        uint48 epoch,
        uint8 pool,
        uint256 amount,
        bytes32[] calldata proof
    ) external nonReentrant {
        _claim(epoch, pool, msg.sender, msg.sender, amount, proof);
    }

    /// @notice Claim to a different recipient address.
    function claimTo(
        uint48 epoch,
        uint8 pool,
        address account,
        address to,
        uint256 amount,
        bytes32[] calldata proof
    ) external nonReentrant {
        require(msg.sender == account, "only account"); // prevent others steering funds unless desired
        _claim(epoch, pool, account, to, amount, proof);
    }

    /// @notice Batch multiple claims.
    struct ClaimParam {
        uint48 epoch;
        uint8  pool;
        uint256 amount;
        bytes32[] proof;
    }

    function claimMany(ClaimParam[] calldata claims) external nonReentrant {
        for (uint256 i = 0; i < claims.length; i++) {
            _claim(claims[i].epoch, claims[i].pool, msg.sender, msg.sender, claims[i].amount, claims[i].proof);
        }
    }

    // ---------------- Internal ----------------

    function _claim(
        uint48 epoch,
        uint8 pool,
        address account,
        address to,
        uint256 amount,
        bytes32[] calldata proof
    ) internal {
        RootConfig memory rc = roots[epoch][pool];
        require(rc.active, "root inactive");
        require(!claimed[epoch][pool][account], "already claimed");

        // leaf schema: keccak256(chainId, epoch, pool, account, token, amount)
        bytes32 leaf = keccak256(abi.encodePacked(block.chainid, epoch, pool, account, rc.token, amount));
        require(MerkleProof.verify(proof, rc.merkleRoot, leaf), "bad proof");

        claimed[epoch][pool][account] = true;
        IERC20(rc.token).safeTransfer(to, amount);

        emit Claimed(epoch, pool, account, rc.token, amount, to);
    }

    // ---------------- Rescue ----------------

    function rescueERC20(address token, address to, uint256 amount) external onlyOwner {
        IERC20(token).safeTransfer(to, amount);
    }
}

/**
 * @title D223 Root Manager
 * @notice Publishes epoch+pool Merkle roots (with optional timelock) to a MerkleDistributor.
 *         Path A (MVP): set minDelay=0 and call `commitRoot` directly (multisig owner).
 *         Path B (Pro): set a >0 minDelay, queue with `queueRoot`, then `executeRoot` after ETA.
 */

import "@openzeppelin/contracts/access/Ownable2Step.sol";

interface IMerkleDistributor {
    function setRoot(uint48 epoch, uint8 pool, bytes32 merkleRoot, address token, string calldata epochCid) external;
}

contract RootManager is Ownable2Step {
    IMerkleDistributor public immutable distributor;
    uint48 public minDelay; // seconds; 0 for immediate

    constructor(address _distributor, uint48 _minDelay, address initialOwner) Ownable(initialOwner) {
        require(_distributor != address(0), "distributor=0");
        distributor = IMerkleDistributor(_distributor);
        minDelay = _minDelay;
    }

    function setMinDelay(uint48 newDelay) external onlyOwner {
        minDelay = newDelay;
        emit MinDelayUpdated(newDelay);
    }

    // ------------ Path A: immediate commit ------------

    function commitRoot(
        uint48 epoch,
        uint8 pool,
        bytes32 merkleRoot,
        address token,
        string calldata epochCid
    ) external onlyOwner {
        require(minDelay == 0, "delay>0 use queue");
        distributor.setRoot(epoch, pool, merkleRoot, token, epochCid);
        emit RootCommitted(epoch, pool, merkleRoot, token, epochCid);
    }

    // ------------ Path B: timelocked queue ------------

    struct RootProposal {
        uint256 id;
        uint48 epoch;
        uint8 pool;
        bytes32 merkleRoot;
        address token;
        string epochCid;
        uint48 eta;      // earliest execution time
        bool executed;
    }

    uint256 public nextId = 1;
    mapping(uint256 => RootProposal) public proposals;

    function queueRoot(
        uint48 epoch,
        uint8 pool,
        bytes32 merkleRoot,
        address token,
        string calldata epochCid,
        uint48 eta
    ) external onlyOwner returns (uint256 id) {
        require(minDelay > 0, "delay=0 use commit");
        require(eta >= uint48(block.timestamp) + minDelay, "eta too soon");
        id = nextId++;
        proposals[id] = RootProposal({
            id: id,
            epoch: epoch,
            pool: pool,
            merkleRoot: merkleRoot,
            token: token,
            epochCid: epochCid,
            eta: eta,
            executed: false
        });
        emit RootQueued(id, epoch, pool, merkleRoot, token, epochCid, eta);
    }

    function executeRoot(uint256 id) external onlyOwner {
        RootProposal storage p = proposals[id];
        require(p.id != 0, "no proposal");
        require(!p.executed, "executed");
        require(p.eta <= uint48(block.timestamp), "eta not reached");

        p.executed = true;
        distributor.setRoot(p.epoch, p.pool, p.merkleRoot, p.token, p.epochCid);
        emit RootExecuted(id, p.epoch, p.pool, p.merkleRoot, p.token, p.epochCid);
    }

    // ------------ Events ------------

    event MinDelayUpdated(uint48 newDelay);
    event RootCommitted(uint48 indexed epoch, uint8 indexed pool, bytes32 merkleRoot, address token, string epochCid);
    event RootQueued(
        uint256 indexed id,
        uint48 indexed epoch,
        uint8 indexed pool,
        bytes32 merkleRoot,
        address token,
        string epochCid,
        uint48 eta
    );
    event RootExecuted(
        uint256 indexed id,
        uint48 indexed epoch,
        uint8 indexed pool,
        bytes32 merkleRoot,
        address token,
        string epochCid
    );
}

/**
 * @title D223 Referral Registry
 * @notice One-time, wallet-bound referral mapping. Simple anti-self rule. No KYC, no rewards logic on-chain.
 *         Off-chain engine uses this mapping to calculate decayed/capped rewards.
 */

import "@openzeppelin/contracts/access/AccessControl.sol";

contract ReferralRegistry is AccessControl {
    bytes32 public constant IMPORTER_ROLE = keccak256("IMPORTER_ROLE");

    // referee => referrer
    mapping(address => address) public referrerOf;

    event ReferralSet(address indexed referee, address indexed referrer);
    event ReferralImported(address indexed referee, address indexed referrer);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    /// @notice A user sets their referrer (once). Cannot be self, cannot overwrite.
    function setReferrer(address referrer) external {
        require(referrer != address(0), "referrer=0");
        require(referrer != msg.sender, "self-referral");
        require(referrerOf[msg.sender] == address(0), "already set");
        referrerOf[msg.sender] = referrer;
        emit ReferralSet(msg.sender, referrer);
    }

    /// @notice Admin/Importer can backfill from legacy systems. Won't overwrite existing.
    function importReferral(address referee, address referrer) external onlyRole(IMPORTER_ROLE) {
        require(referee != address(0) && referrer != address(0), "zero addr");
        require(referee != referrer, "self");
        require(referrerOf[referee] == address(0), "exists");
        referrerOf[referee] = referrer;
        emit ReferralImported(referee, referrer);
    }
}

/**
 * @title D223 Wallet Linker (EIP-712)
 * @notice Consent-based linking of secondary wallets into a "cluster" under a primary.
 *         The *linked* wallet must sign an EIP-712 message authorizing linkage.
 *         Unlink can be done by primary or the linked wallet.
 */

import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract WalletLinker is EIP712 {
    using ECDSA for bytes32;

    string private constant NAME = "D223 WalletLinker";
    string private constant VERSION = "1";
    bytes32 private constant LINK_TYPEHASH =
        keccak256("Link(address primary,address linked,uint256 nonce,uint256 deadline)");

    // linked => primary
    mapping(address => address) public linkedTo;
    // primary => cluster members (does not include primary itself)
    mapping(address => address[]) private clusterMembers;
    // nonces per linked wallet for replay protection
    mapping(address => uint256) public nonces;

    event Linked(address indexed primary, address indexed linked);
    event Unlinked(address indexed primary, address indexed linked);

    constructor() EIP712(NAME, VERSION) {}

    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    /// @notice Link a wallet into a primary's cluster using a signature from the linked wallet.
    function linkWithSig(
        address primary,
        address linked,
        uint256 deadline,
        uint8 v, bytes32 r, bytes32 s
    ) external {
        require(primary != address(0) && linked != address(0), "zero addr");
        require(primary != linked, "self");
        require(block.timestamp <= deadline, "expired");
        require(linkedTo[linked] == address(0), "already linked");

        uint256 nonce = nonces[linked];
        bytes32 structHash = keccak256(abi.encode(LINK_TYPEHASH, primary, linked, nonce, deadline));
        bytes32 digest = _hashTypedDataV4(structHash);
        address signer = ECDSA.recover(digest, v, r, s);
        require(signer == linked, "bad sig");

        nonces[linked] = nonce + 1;
        linkedTo[linked] = primary;
        clusterMembers[primary].push(linked);
        emit Linked(primary, linked);
    }

    /// @notice Unlink a member from a cluster. Callable by the primary or the member itself.
    function unlink(address member) external {
        address primary = linkedTo[member];
        require(primary != address(0), "not linked");
        require(msg.sender == primary || msg.sender == member, "no auth");

        // clear mapping
        linkedTo[member] = address(0);

        // remove from array (swap & pop)
        address[] storage arr = clusterMembers[primary];
        for (uint256 i = 0; i < arr.length; i++) {
            if (arr[i] == member) {
                arr[i] = arr[arr.length - 1];
                arr.pop();
                break;
            }
        }

        emit Unlinked(primary, member);
    }

    function getCluster(address primary) external view returns (address[] memory) {
        return clusterMembers[primary];
    }
}
