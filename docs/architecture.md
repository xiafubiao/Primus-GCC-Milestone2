# Architecture Overview

## System Design

This document describes the architecture of the zkTLS × zkVM integration system for Primus Network GCC Milestone 2.

## Core Components

### 1. zkTLS-zkVM Connection Module

The bridge between zkTLS attestations and zkVM proof systems.

**Responsibilities:**
- Parse EIP712 attestation data
- Extract and validate attestation fields
- Convert attestation data to zkVM-friendly format
- Generate verification inputs for zkVM circuits

**Key Files:**
- `src/core/attestation_verifier.ts` - Main verification logic
- `src/core/data_extractor.ts` - Extract plain response from attestation
- `src/core/proof_bridge.ts` - Bridge attestation data to zkVM proofs

### 2. Attestation Data Structure

```typescript
interface AttestationData {
  attestor: string;           // Attestor's address
  taskId: string;             // Task identifier
  attestation: {
    recipient: string;        // User's wallet address
    request: {
      url: string;            // Request URL
      header: Record<string, string>;
      method: string;         // HTTP method
      body: string;           // Request body
    };
    responseResolve: {
      keyName: string;        // Verification data item name
      parseType: string;      // JSON | XPath | etc.
      parsePath: string;      // Path to data item
    }[];
    data: Record<string, any>; // Actual data items (stringified JSON)
    attConditions: string;     // Response conditions (stringified JSON)
    timestamp: number;         // Verification execution timestamp
    additionParams: string;    // Additional parameters from zkTLS SDK
  };
  signature: {
    v: number;
    r: string;
    s: string;
  };
  txHash?: string;            // Transaction hash (optional)
}
```

### 3. Verification Flow

```
┌─────────────────────────────────────────────────────────────────────────┐
│ Step 1: Dapp Submits Task to Primus Network                             │
│ - Input: Task configuration (URL, headers, responseResolve, etc.)       │
│ - Output: taskId, list of assigned attestors                            │
└─────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Step 2: Dapp Performs zkTLS with Attestors                              │
│ - Dapp → Attestor: Attestation request (taskId, request, etc.)          │
│ - Attestor → Dapp: attestation_data                                     │
│   {                                                                     │
│     public_data: [                                                      │
│       {                                                                 │
│         attestation: { recipient, request, responseResolves, data... }, │
│         signature: string                                               │
│       }                                                                 │
│     ],                                                                  │
│     private_data: [                                                     │
│       { random?: string[], content?: string[],                          │
│         plain_json_response?: [...] }                                   │
│     ]                                                                   │
│   }                                                                     │
└─────────────────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Step 3: Dapp Prepares attestation_data for zkVM                         │
│ - public_data: hash/commitment, signature, attestation metadata         │
│ - private_data: raw_data (plain_response), random (if commitment-based) │
│ - No separate "plain_response" - it's part of private_data              │
└─────────────────────────────────────────────────────────────────────────┘
                                   │
                                   │ 4. Send to zkVM
                                   │    attestation data: {
                                   │      public_data (hash/commitment),
                                   │      private_data (raw data)
                                   │    }
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Step 4: zkVM Verification Program (Inside TEE)                          │
│ Input: attestation data { public_data (hash/commitment), private_data (raw data) }
│                                                                         │
│ ┌─────────────────────────────────────────────────────────────────────┐ │
│ │  Verification & Business Logic Program                              │ │
│ │  - Verify EIP712 signature (ECDSA secp256k1)                        │ │
│ │  - Verify request_url matches one of allowed_urls                   │ │
│ │  - Verify response integrity:                                       │ │
│ │    • Commitment-based: coms[i] == msgs_chunks[i]*G + rnds[i]*H      │ │
│ │    • Hash-based: data_hashes[i] == sha256(response_content[i])      │ │
│ │  - Extract JSON fields from private_data                            │ │
│ │  - Execute custom verification logic                                │ │
│ │  - Generate proof / emit verification result                        │ │
│ └─────────────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────────────┘
                                   │
                                   │ Output from zkVM:
                                   │ {
                                   │   proof,
                                   │   public_inputs,
                                   │   verification_result
                                   │ }
                                   ▼
┌─────────────────────────────────────────────────────────────────────────┐
│ Step 5: Return Proof to Dapp / Submit On-Chain                          │
│ - Dapp receives zkVM proof                                              │
│ - Optionally submit to on-chain verifier contract                       │
│ - Verify proof and consume verification result                          │
└─────────────────────────────────────────────────────────────────────────┘
```

**Key Points:**
- **Attestor → Dapp**: Returns `attestation_data` (public + private)
- **Dapp → zkVM**: Sends `attestation_data` to the zkVM program
- **zkVM**: Verifies attestation integrity + executes business logic

## Attestation Types

### Commitment-based (Grumpkin Curve)

**Use Case:** Large datasets, batch verification

**Structure:**
```typescript
interface CommitmentAttestation {
  publicKeyX: Uint8Array;
  publicKeyY: Uint8Array;
  hash: Uint8Array;
  signature: Uint8Array;
  requestUrls: BoundedVec[];
  allowedUrls: BoundedVec[];
  commitments: EmbeddedCurvePoint[];  // coms[i]
  randomScalars: Field[];              // rnds[i]
  msgsChunks: Field[];                 // msgs_chunks[i]
  msgs: Uint8Array[];
  H: EmbeddedCurvePoint;               // Fixed per business case
  id: Field;
}
```

**Verification Equation:**
```
coms[i] == msgs_chunks[i] * G + rnds[i] * H
```

Where:
- `G` is the fixed generator point
- `H` is the fixed point per business case
- `coms[i]` are the commitments
- `msgs_chunks[i]` are message chunks
- `rnds[i]` are random scalars

### Hashing-based (SHA256)

**Use Case:** Small datasets, simpler circuits

**Structure:**
```typescript
interface HashAttestation {
  publicKeyX: Uint8Array;
  publicKeyY: Uint8Array;
  hash: Uint8Array;
  signature: Uint8Array;
  requestUrls: BoundedVec[];
  allowedUrls: BoundedVec[];
  dataHashes: Uint8Array[];  // sha256(plain_json_response_contents[i])
  msgs: Uint8Array[];
  id: Field;
}
```

**Verification:**
```
data_hashes[i] == sha256(plain_json_response_contents[i])
```

## zkVM Platform Integration

### Aztec Noir

**Adapter Location:** `src/platforms/aztec/`

**Components:**
- `noir_verifier.nr` - Noir verification circuit
- `parser.ts` - TypeScript parser for attestation JSON
- `contract_template.nr` - Aztec smart contract template

**Key Functions:**
- `verify_attestation_comm()` - Commitment-based verification
- `verify_attestation_hashing()` - Hash-based verification

**Workflow:**
1. Parse attestation JSON using `att_verifier_parsing`
2. Deploy Aztec contract using `aztec-attestation-sdk`
3. Call `verify_comm()` or `verify_hash()` with parsed inputs
4. Wait for public event emission (confirms full verification)

### Succinct SP1

**Adapter Location:** `src/platforms/succinct/`

**Components:**
- `sp1_verifier.rs` - Rust verification program for SP1
- Integration with SP1 zkVM runtime

**Features:**
- High-throughput verification
- Optimized for batch processing
- Native Rust implementation

### Brevis Pico

**Adapter Location:** `src/platforms/brevis/`

**Components:**
- `pico_verifier.rs` - Lightweight verification for Pico zkVM

**Features:**
- Minimal proof size
- Mobile/edge deployment optimized
- Fast verification time

## Performance Considerations

### Circuit Size Optimization

**Target Constraints:**
- Small cases: < 350k constraints
- Medium cases: < 500k constraints
- Large cases: < 800k constraints

**Optimization Techniques:**
1. Batch commitment verification
2. Efficient SHA256 implementation
3. Grumpkin curve optimization
4. Constraint reduction in URL matching

### Latency Targets

**End-to-End (including blockchain):**
- Local sandbox: < 40s
- Devnet: < 45s
- Mainnet: < 60s (depends on block time)

**Proving Time Only:**
- Small circuits: < 10s
- Medium circuits: < 20s
- Large circuits: < 30s

## Security Considerations

### TEE (Trusted Execution Environment)

The Verification Program runs inside a TEE to ensure:
- Attestation signature verification is tamper-proof
- Plain response extraction is secure
- Business logic execution is isolated

### Cryptographic Guarantees

1. **Signature Verification**: EIP712 signature must be valid
2. **URL Matching**: Request URL must match one of allowed URLs
3. **Data Integrity**: Commitments/hashes must match actual data
4. **Freshness**: Timestamp must be within acceptable range

## Next Steps

1. Implement core attestation verifier (`src/core/attestation_verifier.ts`)
2. Complete Aztec Noir adapter (priority: high)
3. Develop Succinct SP1 adapter (priority: medium)
4. Create Brevis Pico adapter (priority: medium)
5. Add comprehensive tests and benchmarks
6. Optimize circuit performance

## References

- [DVC Workflow](https://github.com/primus-labs/DVC-Intro)
- [zkTLS Verification Noir](https://github.com/primus-labs/zktls-verification-noir)
- [Aztec Network Docs](https://docs.aztec.network)
- [EAS Standard](https://easscan.org)
