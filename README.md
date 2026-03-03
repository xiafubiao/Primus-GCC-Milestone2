# Primus GCC Milestone 2

zkTLS Attestation Project - Primus Network GCC Milestone 2

## Overview

This repository contains the implementation for Primus Network's zkTLS (Zero-Knowledge Transport Layer Security) attestation system, developed as part of the GCC Milestone 2 program.

## Features

- **zkTLS Proofs**: Generate zero-knowledge proofs for HTTPS/TLS session data
- **EAS Attestations**: Create Ethereum Attestation Service compliant attestations
- **Data Verification**: Verify off-chain data with on-chain attestations
- **Privacy-Preserving**: Prove data authenticity without revealing sensitive information

## Tech Stack

- **Blockchain**: BSC (Binance Smart Chain)
- **Attestation Standard**: EAS (Ethereum Attestation Service)
- **Signature**: EIP712
- **zkTLS Provider**: Primus Network

## Getting Started

### Prerequisites

- Node.js >= 18
- npm or yarn
- A wallet with BSC testnet/mainnet access

### Installation

```bash
npm install
```

### Configuration

Create a `.env` file with the following variables:

```env
PRIVATE_KEY=your_wallet_private_key
RPC_URL=https://bsc-dataseed.binance.org
CONTRACT_ADDRESS=0x...
```

### Usage

```bash
# Generate attestation
npm run attest

# Verify attestation
npm run verify
```

## Project Structure

```
├── src/
│   ├── attest.ts      # Attestation generation
│   ├── verify.ts      # Attestation verification
│   └── utils.ts       # Utility functions
├── tests/
├── .env.example
├── package.json
└── README.md
```

## Resources

- [Primus Network Documentation](https://docs.primus.network)
- [EAS Documentation](https://easscan.org)
- [zkTLS Specification](https://zktls.com)

## License

MIT
