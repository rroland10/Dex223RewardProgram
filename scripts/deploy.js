const { ethers } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();
  
  console.log("Deploying contracts with the account:", deployer.address);
  console.log("Account balance:", (await deployer.getBalance()).toString());

  // Deploy Dex223Token
  console.log("\nDeploying Dex223Token...");
  const Dex223Token = await ethers.getContractFactory("Dex223Token");
  const token = await Dex223Token.deploy(
    "Dex223 Token",
    "DEX223",
    18,
    deployer.address
  );
  await token.deployed();
  console.log("Dex223Token deployed to:", token.address);

  // Deploy Dex223RewardsEnhanced
  console.log("\nDeploying Dex223RewardsEnhanced...");
  const Dex223RewardsEnhanced = await ethers.getContractFactory("Dex223RewardsEnhanced");
  const rewards = await Dex223RewardsEnhanced.deploy(deployer.address);
  await rewards.deployed();
  console.log("Dex223RewardsEnhanced deployed to:", rewards.address);

  // Set token support
  console.log("\nSetting token support...");
  await rewards.setTokenSupport(token.address, true);
  console.log("Token support set for:", token.address);

  // Mint initial tokens to rewards contract
  console.log("\nMinting initial tokens...");
  const initialSupply = ethers.utils.parseEther("1000000"); // 1M tokens
  await token.mint(rewards.address, initialSupply);
  console.log("Minted", ethers.utils.formatEther(initialSupply), "tokens to rewards contract");

  console.log("\n=== Deployment Summary ===");
  console.log("Dex223Token:", token.address);
  console.log("Dex223RewardsEnhanced:", rewards.address);
  console.log("Admin:", deployer.address);
  console.log("Initial token supply:", ethers.utils.formatEther(initialSupply));

  // Save deployment info
  const deploymentInfo = {
    network: hre.network.name,
    chainId: hre.network.config.chainId,
    timestamp: new Date().toISOString(),
    deployer: deployer.address,
    contracts: {
      Dex223Token: token.address,
      Dex223RewardsEnhanced: rewards.address
    },
    initialSupply: ethers.utils.formatEther(initialSupply)
  };

  const fs = require('fs');
  const path = require('path');
  const deploymentsDir = path.join(__dirname, '..', 'deployments');
  if (!fs.existsSync(deploymentsDir)) {
    fs.mkdirSync(deploymentsDir);
  }
  
  const deploymentFile = path.join(deploymentsDir, `${hre.network.name}.json`);
  fs.writeFileSync(deploymentFile, JSON.stringify(deploymentInfo, null, 2));
  console.log("\nDeployment info saved to:", deploymentFile);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
