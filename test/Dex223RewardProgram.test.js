const { expect } = require("chai");
const { ethers } = require("hardhat");
const { MerkleTree } = require("merkletreejs");

describe("Dex223RewardProgram", function () {
  let token, rewards, admin, user1, user2, user3;
  let merkleTree, merkleRoot;

  beforeEach(async function () {
    [admin, user1, user2, user3] = await ethers.getSigners();

    // Deploy Dex223Token
    const Dex223Token = await ethers.getContractFactory("Dex223Token");
    token = await Dex223Token.deploy("Dex223 Token", "DEX223", 18, await admin.getAddress());
    await token.waitForDeployment();

    // Deploy Dex223RewardsEnhanced
    const Dex223RewardsEnhanced = await ethers.getContractFactory("Dex223RewardsEnhanced");
    rewards = await Dex223RewardsEnhanced.deploy(await admin.getAddress());
    await rewards.waitForDeployment();

    // Set token support
    await rewards.setTokenSupport(await token.getAddress(), true);

    // Create merkle tree for testing
    const leaves = [
      ethers.solidityPackedKeccak256(["address", "uint256"], [await user1.getAddress(), ethers.parseEther("100")]),
      ethers.solidityPackedKeccak256(["address", "uint256"], [await user2.getAddress(), ethers.parseEther("200")]),
      ethers.solidityPackedKeccak256(["address", "uint256"], [await user3.getAddress(), ethers.parseEther("300")])
    ];
    merkleTree = new MerkleTree(leaves, ethers.keccak256, { sortPairs: true });
    merkleRoot = merkleTree.getHexRoot();

    // Mint tokens to rewards contract
    await token.mint(await rewards.getAddress(), ethers.parseEther("10000"));
  });

  describe("Token Deployment", function () {
    it("Should deploy with correct parameters", async function () {
      expect(await token.name()).to.equal("Dex223 Token");
      expect(await token.symbol()).to.equal("DEX223");
      expect(await token.decimals()).to.equal(18);
      expect(await token.balanceOf(await rewards.getAddress())).to.equal(ethers.parseEther("10000"));
    });
  });

  describe("Epoch Configuration", function () {
    it("Should configure epoch successfully", async function () {
      const epoch = 1;
      const totalAllocated = ethers.parseEther("1000");
      const startTime = Math.floor(Date.now() / 1000);
      const endTime = startTime + 86400; // 1 day

      await rewards.configureEpoch(
        epoch,
        await token.getAddress(),
        merkleRoot,
        totalAllocated,
        startTime,
        endTime
      );

      const epochInfo = await rewards.getEpochInfo(epoch);
      expect(epochInfo.merkleRoot).to.equal(merkleRoot);
      expect(epochInfo.rewardToken).to.equal(await token.getAddress());
      expect(epochInfo.totalAllocated).to.equal(totalAllocated);
      expect(epochInfo.isActive).to.be.true;
    });

    it("Should reject unsupported tokens", async function () {
      const epoch = 1;
      const totalAllocated = ethers.parseEther("1000");
      const startTime = Math.floor(Date.now() / 1000);

      await expect(
        rewards.configureEpoch(
          epoch,
          await user1.getAddress(), // Random address, not a supported token
          merkleRoot,
          totalAllocated,
          startTime,
          0
        )
      ).to.be.revertedWith("UNSUPPORTED_TOKEN");
    });
  });

  describe("Claiming", function () {
    beforeEach(async function () {
      // Configure epoch
      const epoch = 1;
      const totalAllocated = ethers.parseEther("1000");
      const startTime = Math.floor(Date.now() / 1000) - 3600; // 1 hour ago
      const endTime = startTime + 86400; // 1 day

      await rewards.configureEpoch(
        epoch,
        await token.getAddress(),
        merkleRoot,
        totalAllocated,
        startTime,
        endTime
      );

      // Fund the epoch
      await rewards.fundEpoch(epoch, ethers.parseEther("1000"));
    });

    it("Should claim rewards successfully", async function () {
      const epoch = 1;
      const amount = ethers.parseEther("100");
      const leaf = ethers.solidityPackedKeccak256(["address", "uint256"], [await user1.getAddress(), amount]);
      const proof = merkleTree.getHexProof(leaf);

      const initialBalance = await token.balanceOf(await user1.getAddress());
      
      await rewards.connect(user1).claim(epoch, await user1.getAddress(), amount, proof, ethers.ZeroAddress);
      
      const finalBalance = await token.balanceOf(await user1.getAddress());
      expect(finalBalance - initialBalance).to.equal(amount);
    });

    it("Should reject invalid merkle proof", async function () {
      const epoch = 1;
      const amount = ethers.parseEther("100");
      const invalidLeaf = ethers.solidityPackedKeccak256(["address", "uint256"], [await user1.getAddress(), ethers.parseEther("50")]);
      const proof = merkleTree.getHexProof(invalidLeaf);

      await expect(
        rewards.connect(user1).claim(epoch, await user1.getAddress(), amount, proof, ethers.ZeroAddress)
      ).to.be.revertedWith("INVALID_PROOF");
    });

    it("Should reject claims below minimum amount", async function () {
      const epoch = 1;
      const amount = ethers.parseEther("0.5"); // Below 1 token minimum
      const leaf = ethers.solidityPackedKeccak256(["address", "uint256"], [await user1.getAddress(), amount]);
      const proof = merkleTree.getHexProof(leaf);

      await expect(
        rewards.connect(user1).claim(epoch, await user1.getAddress(), amount, proof, ethers.ZeroAddress)
      ).to.be.revertedWith("BELOW_MINIMUM");
    });

    it("Should reject double claims", async function () {
      const epoch = 1;
      const amount = ethers.parseEther("100");
      const leaf = ethers.solidityPackedKeccak256(["address", "uint256"], [await user1.getAddress(), amount]);
      const proof = merkleTree.getHexProof(leaf);

      // First claim
      await rewards.connect(user1).claim(epoch, await user1.getAddress(), amount, proof, ethers.ZeroAddress);
      
      // Second claim should fail with ALREADY_CLAIMED
      await expect(
        rewards.connect(user1).claim(epoch, await user1.getAddress(), amount, proof, ethers.ZeroAddress)
      ).to.be.revertedWith("ALREADY_CLAIMED");
    });
  });

  describe("Referral System", function () {
    beforeEach(async function () {
      // Configure epoch
      const epoch = 1;
      const totalAllocated = ethers.parseEther("1000");
      const startTime = Math.floor(Date.now() / 1000) - 3600;
      const endTime = startTime + 86400;

      await rewards.configureEpoch(
        epoch,
        await token.getAddress(),
        merkleRoot,
        totalAllocated,
        startTime,
        endTime
      );

      // Fund the epoch
      await rewards.fundEpoch(epoch, ethers.parseEther("1000"));
    });

    it("Should distribute referral rewards correctly", async function () {
      const epoch = 1;
      const amount = ethers.parseEther("100");
      const leaf = ethers.solidityPackedKeccak256(["address", "uint256"], [await user1.getAddress(), amount]);
      const proof = merkleTree.getHexProof(leaf);

      const initialUserBalance = await token.balanceOf(await user1.getAddress());
      const initialReferrerBalance = await token.balanceOf(await user2.getAddress());
      
      await rewards.connect(user1).claim(epoch, await user1.getAddress(), amount, proof, await user2.getAddress());
      
      const finalUserBalance = await token.balanceOf(await user1.getAddress());
      const finalReferrerBalance = await token.balanceOf(await user2.getAddress());
      
      // 10% referral (1000 bps)
      const referralAmount = (amount * 1000n) / 10000n;
      const userAmount = amount - referralAmount;
      
      expect(finalUserBalance - initialUserBalance).to.equal(userAmount);
      expect(finalReferrerBalance - initialReferrerBalance).to.equal(referralAmount);
    });
  });
});
