# Dex223RewardProgram

Enhanced Dex223 — ERC223 Token + Advanced Merkle-based Rewards Distributor

## Overview

This project implements a comprehensive reward distribution system with the following components:

- **Dex223Token**: ERC223-compliant token with ERC20-style allowances, access control, and pausable functionality
- **Dex223RewardsEnhanced**: Advanced Merkle proof-based rewards distributor with anti-Sybil mechanisms

## Features

### Dex223Token
- ERC223 token standard implementation
- ERC20-style allowances for compatibility
- Access control with admin and minter roles
- Pausable functionality
- Minting and burning capabilities

### Dex223RewardsEnhanced
- Merkle proof-based reward claims
- Anti-Sybil mechanisms:
  - Minimum claim amounts
  - Cooldown periods between claims
- Multi-token support with whitelisting
- Epoch-based reward distribution
- Referral system with configurable percentages
- Token recovery mechanism for wrong deposits

## Installation

```bash
npm install
```

## Compilation

```bash
npm run compile
```

## Testing

```bash
npm test
```

## Deployment

### Local Network
```bash
npm run deploy:local
```

### Sepolia Testnet
```bash
npm run deploy:sepolia
```

### Mainnet
```bash
npm run deploy:mainnet
```

## Usage

### 1. Deploy Contracts
Deploy both the token and rewards contracts using the deployment script.

### 2. Configure Epoch
```solidity
// Configure a new epoch
rewards.configureEpoch(
    epochId,
    tokenAddress,
    merkleRoot,
    totalAllocated,
    startTime,
    endTime
);
```

### 3. Fund Epoch
```solidity
// Fund the epoch with tokens
rewards.fundEpoch(epochId, amount);
```

### 4. Claim Rewards
```solidity
// Users claim their rewards
rewards.claim(
    epochId,
    account,
    amount,
    merkleProof,
    referrer
);
```

## Security Features

- **Access Control**: Role-based permissions for admin and operator functions
- **Pausable**: Emergency stop functionality
- **Reentrancy Protection**: Prevents reentrancy attacks
- **Anti-Sybil**: Minimum amounts and cooldown periods
- **Token Validation**: Whitelist for supported reward tokens
- **Recovery Mechanism**: Safe recovery of wrongly sent tokens

## License

GPL-3.0-or-later

## Copyright

Copyright (C) 2025 Dex223
