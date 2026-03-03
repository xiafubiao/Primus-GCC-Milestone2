# Primus GCC Milestone 2

zkTLS × zkVM Integration - Primus Network GCC Milestone 2 Implementation

## 📋 Milestone Objectives

**Completion Target: 30%**

### Core Deliverables

1. **zkTLS-zkVM Connection Algorithm Module**
   - Implement trusted verification of off-chain data in zero-knowledge environments
   - Bridge zkTLS attestations with zkVM proof systems

2. **Multi-zkVM Platform Support**
   - **Aztec Noir**: Commitment-based and hashing-based attestation verification
   - **Succinct**: SP1 integration for zkTLS verification circuits
   - **Brevis**: Pico zkVM adapter for attestation validation

3. **zkTLS Algorithm Optimization**
   - Introduce zkSNARK-friendly cryptographic primitives
   - Reduce proof computation latency for zkVM execution
   - Foundation for future performance scaling

## 🏗️ Architecture

### DVC (Data Verification and Computation) Mode

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           Dapp (Primus SDK)                             │
│                                                                         │
│  1. Submit Task          3. Extract Plain Response (local)              │
│     ┌─────────┐              ┌───────────────────────┐                  │
│     │ Contract│              │  plain_response       │                  │
│     └────┬────┘              └───────────────────────┘                  │
│          │                              │                                │
│          ▼                              │                                │
│  2. Return Attestation                  │                                │
│     ┌───────────────────────────────────┤                                │
│     │  attestation_data                 │                                │
│     │  ├─ public_data                   │                                │
│     │  │   ├─ attestation (JSON)        │                                │
│     │  │   └─ signature                 │                                │
│     │  └─ private_data                  │                                │
│     │      └─ content / random          │                                │
│     └───────────────────────────────────┤                                │
│                                        │                                │
└────────────────────────────────────────┼────────────────────────────────┘
                                         │
                                         │ 4. Send to zkVM
                                         │    attestation data: {
                                         │      public_data (hash/commitment),
                                         │      private_data (raw data)
                                         │    }
                                         ▼
                    ┌────────────────────────────────────────────────┐
                    │     Verification Program (TEE + zkVM)          │
                    │                                                │
                    │  ┌──────────────────────────────────────────┐  │
                    │  │  Verification & Business Logic Program   │  │
                    │  │  1. Verify attestation signature         │  │
                    │  │  2. Validate URL & response integrity    │  │
                    │  │  3. Extract JSON fields                  │  │
                    │  │  4. Execute custom verification          │  │
                    │  │  5. Emit result / generate proof         │  │
                    │  └──────────────────────────────────────────┘  │
                    │                                                │
                    └────────────────────────────────────────────────┘
                                         │
                                         │ 5. Return Proof
                                         ▼
                    ┌────────────────────────────────────────────────┐
                    │         On-Chain Verifier / Dapp               │
                    └────────────────────────────────────────────────┘
```

**Key Points:**
- **Attestor → Dapp**: Returns `attestation_data` (public + private)
- **Dapp → zkVM**: Sends `attestation_data` to the zkVM program
- **zkVM**: Verifies attestation integrity + executes business logic
- **zkVM**: Verifies attestation integrity + executes business logic
- **No direct Attestor → zkVM connection**: All data flows through Dapp

## 📁 Project Structure

```
Primus-GCC-Milestone2/
├── README.md
├── docs/
│   ├── architecture.md          # System architecture details
│   ├── zkvm-integration/        # zkVM platform integration guides
│   │   ├── aztec-noir.md
│   │   ├── succinct-sp1.md
│   │   └── brevis-pico.md
│   └── optimization/            # Performance optimization notes
│       └── zksnark-primitives.md
├── src/
│   ├── core/                    # Core zkTLS-zkVM connection module
│   │   ├── attestation_verifier.ts
│   │   ├── data_extractor.ts
│   │   └── proof_bridge.ts
│   ├── platforms/               # zkVM platform adapters
│   │   ├── aztec/
│   │   │   ├── noir_verifier.nr
│   │   │   ├── parser.ts
│   │   │   └── contract_template.nr
│   │   ├── succinct/
│   │   │   └── sp1_verifier.rs
│   │   └── brevis/
│   │       └── pico_verifier.rs
│   └── utils/                   # Cryptographic utilities
│       ├── grumpkin_curve.ts
│       ├── sha256_optimized.ts
│       └── commitment_utils.ts
├── tests/
│   ├── integration/
│   ├── benchmarks/
│   └── fixtures/
├── examples/
│   ├── aztec-commitment-verify/
│   ├── aztec-hash-verify/
│   └── end-to-end-demo/
├── package.json
├── tsconfig.json
└── .gitignore
```

## 🔧 Technical Components

### 1. Attestation Verification

Two supported attestation types:

- **Commitment-based** (Grumpkin curve)
  - Uses elliptic curve commitments
  - Verification: `coms[i] == msgs_chunks[i]*G + rnds[i]*H`
  - Optimized for batch verification

- **Hashing-based** (SHA256)
  - Uses cryptographic hashing
  - Verification: `data_hashes[i] == sha256(plain_json_response_contents[i])`
  - Simpler circuit, faster for small datasets

### 2. zkVM Platform Adapters

#### Aztec Noir
- Library: `att_verifier_lib` (Noir)
- Parser: `att_verifier_parsing` (TypeScript)
- SDK: `aztec-attestation-sdk`
- Contract template with `verify_comm()` and `verify_hash()` functions

#### Succinct SP1
- Rust-based verification circuits
- Integration with SP1 zkVM runtime
- Optimized for high-throughput verification

#### Brevis Pico
- Lightweight zkVM adapter
- Focus on mobile/edge deployment
- Minimal proof size optimization

### 3. Performance Optimizations

- **zkSNARK-friendly primitives**: Grumpkin curve operations
- **Batch verification**: Process multiple commitments in single circuit
- **Circuit size reduction**: Target <400k constraints for common cases
- **Latency targets**: <45s end-to-end (including blockchain interaction)

## 🚀 Getting Started

### Prerequisites

```bash
# Node.js >= 18
node --version

# Aztec Sandbox (for Noir development)
# https://docs.aztec.network/developers/getting_started_on_local_network

# Rust (for Succinct/Brevis)
rustup install stable
```

### Installation

```bash
git clone https://github.com/xiafubiao/Primus-GCC-Milestone2.git
cd Primus-GCC-Milestone2
npm install
```

### Quick Start - Aztec Example

```bash
# Build libraries
cd src/platforms/aztec/att_verifier_parsing
yarn && yarn build

cd ../aztec-attestation-sdk
yarn && yarn build

# Run devnet example
cd ../../../../examples/aztec-commitment-verify
yarn
yarn start:devnet

# Run local sandbox
PXE_PROVER_ENABLED=1 aztec start --local-network
yarn start:local
```

## 📊 Benchmarks

**Test Environment**: MacBook Air M2 (8-core, 3.49 GHz, 16GB RAM)

| Method | Time (ms) | Circuit Size (constraints) |
|--------|-----------|---------------------------|
| Commitment-based (65 comms) | 41,113 | 711,763 |
| Commitment-based (small) | 36,538 | 321,513 |
| Hash-based | 42,784 | 794,646 |

*Note: These benchmarks include end-to-end transaction submission and blockchain interaction, not just proving time.*

## 📚 Documentation

- [Architecture Overview](docs/architecture.md)
- [Aztec Noir Integration](docs/zkvm-integration/aztec-noir.md)
- [Succinct SP1 Integration](docs/zkvm-integration/succinct-sp1.md)
- [Brevis Pico Integration](docs/zkvm-integration/brevis-pico.md)
- [Optimization Guide](docs/optimization/zksnark-primitives.md)

## 🔌 DVC × Aztec Integration

This repository includes a complete implementation of the DVC (Data Verification and Computation) mode integrated with Aztec Network, based on the official [zktls-verification-noir](https://github.com/primus-labs/zktls-verification-noir) library.

### Implementation Location

```
src/platforms/aztec/
├── att_verifier_lib/          # Noir verification library
│   └── src/lib.nr             # Core verify_attestation_comm/hash functions
├── att_verifier_parsing/      # TypeScript parsing library
│   └── src/                   # JSON → contract input conversion
├── aztec-attestation-sdk/     # SDK for deployment and calls
│   └── src/                   # Client and ContractHelpers
├── contract_template/         # BusinessProgram template
│   └── src/main.nr            # Smart contract with TODO for business logic
└── example/                   # End-to-end examples
    └── js_test/
        ├── verify-commitment-devnet.ts
        └── verify-commitment-local.ts
```

### Quick Start - Aztec DVC

```bash
# 1. Install Aztec Sandbox (version 3.0.0-devnet.6-patch.1)
# https://docs.aztec.network/developers/getting_started_on_local_network

# 2. Build libraries
cd src/platforms/aztec/att_verifier_parsing
yarn && yarn build

cd ../aztec-attestation-sdk
yarn && yarn build

# 3. Compile contract template
cd ../contract_template
aztec-nargo compile
aztec codegen -o src/artifacts target

# 4. Run local example
PXE_PROVER_ENABLED=1 aztec start --local-network
cd ../example/js_test
yarn
yarn start:local

# 5. Or run on devnet
yarn start:devnet
```

### Verification Flow

1. **Dapp** submits task to Primus Network → receives `taskId` and `attestors`
2. **Dapp** performs zkTLS with attestor → receives attestation + signature
3. **Dapp** extracts plain response locally via SDK
4. **Dapp** sends attestation + plain response to Verification Program (TEE + zkVM)
5. **Business Program** calls `verify_attestation_comm/hash` → verifies signature, URL, commitments/hashes
6. **Business Program** executes custom logic → emits success event
7. **zkVM** returns proof to Dapp

### Attestation Types

| Type | Circuit Size | Proving Time | Use Case |
|------|--------------|--------------|----------|
| Commitment (65) | 711k | ~41s | Large datasets, batch verification |
| Commitment (small) | 321k | ~36s | Small number of commitments |
| Hash-based | 794k | ~43s | Simple response verification |

### Key Functions

**Noir (lib.nr):**
- `verify_attestation_comm()` - Commitment-based verification
- `verify_attestation_hashing()` - Hash-based verification

**TypeScript (parsing):**
- `parseCommitmentAttestation()` - Parse JSON for commit-based
- `parseHashingAttestation()` - Parse JSON for hash-based

**SDK:**
- `ContractHelpers.deployContract()` - Deploy verifier contract
- `Client` - Aztec network client (local/devnet)

### Adding Business Logic

In `contract_template/src/main.nr`, add your checks:

```noir
#[external("private")]
fn verify_comm(/* ... */) -> bool {
    let allowed_url_matches_hashes = verify_attestation_comm(/* ... */);
    
    // YOUR BUSINESS LOGIC HERE
    // Example: Parse JSON and verify balance > 1000
    let json = JSON2055::parse_bounded_vec_json(msgs);
    let balance = json.get_number("balance").unwrap();
    assert(balance > 1000, "Balance too low");
    
    BusinessProgram::at(self.address)
        .check_values_emit_event(/* ... */)
        .enqueue(self.context);
    true
}
```

For detailed documentation, see:
- [Aztec Noir Integration Guide](docs/zkvm-integration/aztec-noir.md)
- [Architecture Overview](docs/architecture.md)

---

## 🔗 References

- [Primus Network Docs](https://docs.primuslabs.xyz)
- [DVC Intro](https://github.com/primus-labs/DVC-Intro)
- [DVC Demo](https://github.com/primus-labs/DVC-Demo)
- [zkTLS Verification Noir](https://github.com/primus-labs/zktls-verification-noir)
- [EAS Documentation](https://easscan.org)
- [Aztec Network](https://docs.aztec.network)

## 📝 License

MIT

## 👥 Team

Primus Network GCC Milestone 2 Development Team
