# Aztec Noir Integration Guide

## Overview

This guide covers integrating Primus zkTLS attestations with Aztec Network using Noir, Aztec's domain-specific language for zero-knowledge circuits.

## Components

### 1. att_verifier_lib (Noir Library)

**Location:** `src/platforms/aztec/att_verifier_lib/`

Contains the core Noir verification logic used in smart contracts.

**Key Functions:**

```noir
// Verify commitment-based attestation
fn verify_attestation_comm(
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    hash: [u8; 32],
    signature: [u8; 64],
    request_urls: [BoundedVec<u8, MAX_URL_LEN>; 2],
    allowed_urls: [BoundedVec<u8, MAX_URL_LEN>; 3],
    coms: BoundedVec<EmbeddedCurvePoint, MAX_COMMS>,
    rnds: BoundedVec<Field, MAX_COMMS>,
    msgs_chunks: BoundedVec<Field, MAX_COMMS>,
    H: EmbeddedCurvePoint,
) -> [Field; 2] {
    // 1. Verify signature
    // 2. Verify request_url matches one of allowed_urls
    // 3. Hash the matched allowed_url (output)
    // 4. Verify commitments: coms[i] == msgs_chunks[i]*G + rnds[i]*H
    // 5. Return allowed_url_matches_hashes
}

// Verify hashing-based attestation
fn verify_attestation_hashing(
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    hash: [u8; 32],
    signature: [u8; 64],
    request_urls: [BoundedVec<u8, MAX_URL_LEN>; 2],
    allowed_urls: [BoundedVec<u8, MAX_URL_LEN>; 3],
    data_hashes: BoundedVec<[u8; 32], MAX_HASHES>,
    msgs: BoundedVec<u8, MAX_MSGS_LEN>,
) -> [Field; 2] {
    // 1. Verify signature
    // 2. Verify request_url matches one of allowed_urls
    // 3. Hash the matched allowed_url (output)
    // 4. Verify hashes: data_hashes[i] == sha256(plain_json_response_contents[i])
    // 5. Return allowed_url_matches_hashes
}
```

### 2. att_verifier_parsing (TypeScript Parser)

**Location:** `src/platforms/aztec/att_verifier_parsing/`

Converts attestation JSON into types suitable for Aztec smart contract calls.

**Installation:**

```bash
cd src/platforms/aztec/att_verifier_parsing
yarn install
yarn build
```

**Usage:**

```typescript
import { parseAttestationData } from 'att_verifier_parsing';

const attestationData = JSON.parse(fs.readFileSync(ATT_PATH, 'utf-8'));

const parsed = parseAttestationData(attestationData, {
  maxResponseNum: MAX_RESPONSE_NUM,
  allowedUrls: ALLOWED_URLS,
  grumpkinBatchSize: GRUMPKIN_BATCH_SIZE,
});

// parsed contains:
// - publicKeyX, publicKeyY: Uint8Array[32]
// - hash: Uint8Array[32]
// - signature: Uint8Array[64]
// - requestUrls: BoundedVec[]
// - allowedUrls: BoundedVec[]
// - commitments: EmbeddedCurvePoint[] (for commitment-based)
// - randomScalars: Field[] (for commitment-based)
// - msgsChunks: Field[] (for commitment-based)
// - msgs: Uint8Array[]
// - dataHashes: Uint8Array[32][] (for hash-based)
// - id: Field
```

### 3. aztec-attestation-sdk

**Location:** `src/platforms/aztec/aztec-attestation-sdk/`

SDK for deploying and calling attestation verification contracts.

**Installation:**

```bash
cd src/platforms/aztec/aztec-attestation-sdk
yarn install
yarn build
```

**Usage:**

```typescript
import { Client, ContractHelpers, parseAttestationData } from 'aztec-attestation-sdk';

// Initialize client
const client = new Client({
  nodeUrl: 'https://next.devnet.aztec-labs.com',
  mode: 'devnet'  // or 'local' for local sandbox
});

await client.initialize();
const alice = await client.getAccount();

// For local sandbox:
// const client = new Client({ nodeUrl: 'http://localhost:8080', mode: 'local' });
// const alice = await client.getAccount(0); // instant
```

### 4. contract_template (Smart Contract Template)

**Location:** `src/platforms/aztec/contract_template/`

Template Aztec smart contract for business logic integration.

**Template Structure:**

```noir
contract BusinessProgram {
    // Storage
    admin: Address,
    allowed_url_hashes: [Field; 3],
    H: EmbeddedCurvePoint,  // Only for commitment-based

    // Verify commitment-based attestation
    #[external("private")]
    fn verify_comm(
        public_key_x: [u8; 32],
        public_key_y: [u8; 32],
        hash: [u8; 32],
        signature: [u8; 64],
        request_urls: [BoundedVec<u8, MAX_URL_LEN>; 2],
        allowed_urls: [BoundedVec<u8, MAX_URL_LEN>; 3],
        coms: BoundedVec<EmbeddedCurvePoint, MAX_COMMS>,
        rnds: BoundedVec<Field, MAX_COMMS>,
        msgs_chunks: BoundedVec<Field, MAX_COMMS>,
        msgs: BoundedVec<u8, MAX_MSGS_LEN>,
        H: EmbeddedCurvePoint,
        id: Field,
    ) -> bool {
        // Call attestation verification
        let allowed_url_matches_hashes: [Field; 2] = verify_attestation_comm(
            public_key_x,
            public_key_y,
            hash,
            signature,
            request_urls,
            allowed_urls,
            coms,
            rnds,
            msgs_chunks,
            H,
        );

        // TODO: Insert your business logic checks on msgs here
        // Example: parse msgs, extract fields, verify conditions

        // Emit success event
        BusinessProgram::at(self.address)
            .check_values_emit_event(
                self.msg_sender().unwrap(),
                self.address,
                id,
                allowed_url_matches_hashes,
                H,
            )
            .enqueue(self.context);

        true
    }

    // Verify hashing-based attestation
    #[external("private")]
    fn verify_hash(
        public_key_x: [u8; 32],
        public_key_y: [u8; 32],
        hash: [u8; 32],
        signature: [u8; 64],
        request_urls: [BoundedVec<u8, MAX_URL_LEN>; 2],
        allowed_urls: [BoundedVec<u8, MAX_URL_LEN>; 3],
        data_hashes: BoundedVec<[u8; 32], MAX_HASHES>,
        msgs: BoundedVec<u8, MAX_MSGS_LEN>,
        id: Field,
    ) -> bool {
        // Call attestation verification
        let allowed_url_matches_hashes: [Field; 2] = verify_attestation_hashing(
            public_key_x,
            public_key_y,
            hash,
            signature,
            request_urls,
            allowed_urls,
            data_hashes,
            msgs,
        );

        // TODO: Insert your business logic checks on msgs here

        // Emit success event
        BusinessProgram::at(self.address)
            .check_values_emit_event(
                self.msg_sender().unwrap(),
                self.address,
                id,
                allowed_url_matches_hashes,
            )
            .enqueue(self.context);

        true
    }
}
```

## Complete Workflow Example

### Step 1: Compile Smart Contract

```bash
# In your contract directory (e.g., examples/aztec-commitment-verify)
PXE_PROVER_ENABLED=1 aztec start --local-network
aztec-nargo compile
aztec codegen -o src/artifacts target
```

### Step 2: Move Artifacts

```bash
# Move generated files to bindings directory
cp src/artifacts/*.ts examples/js_test/bindings/
cp target/*.json examples/js_test/bindings/
```

### Step 3: Build Libraries

```bash
# Build parser library
cd src/platforms/aztec/att_verifier_parsing
yarn && yarn build

# Build SDK
cd ../aztec-attestation-sdk
yarn && yarn build
```

### Step 4: Deploy and Verify (Devnet)

```typescript
// examples/js_test/verify-commitment-devnet.ts
import { Client, ContractHelpers, parseAttestationData } from 'aztec-attestation-sdk';
import { BusinessProgramContract } from './bindings/BusinessProgram.js';
import * as fs from 'fs';

// Constants
const ATT_PATH = './fixtures/attestation.json';
const ALLOWED_URLS = [
  'https://api.example.com/data',
  'https://api.example.com/info',
  'https://api.example.com/status'
];
const MAX_RESPONSE_NUM = 10;
const GRUMPKIN_BATCH_SIZE = 65;

// Initialize client
const client = new Client({
  nodeUrl: 'https://next.devnet.aztec-labs.com',
  mode: 'devnet'
});

await client.initialize();
const alice = await client.getAccount();

// Parse attestation data
const attestationData = JSON.parse(fs.readFileSync(ATT_PATH, 'utf-8'));
const parsed = parseAttestationData(attestationData, {
  maxResponseNum: MAX_RESPONSE_NUM,
  allowedUrls: ALLOWED_URLS,
  grumpkinBatchSize: GRUMPKIN_BATCH_SIZE,
});

// Set unique H point for your use case
const H = {
  x: 19978178333943292355349418156359056918133515370613875064303296301489725624535n,
  y: 13201885744872984780649110422697192888453633882501354541258277493771319153464n,
  is_infinite: false
};

// Deploy contract
const contract = await ContractHelpers.deployContract<BusinessProgramContract>(
  BusinessProgramContract,
  client,
  {
    admin: alice.address,
    allowedUrls: ALLOWED_URLS,
    pointH: H,
    from: alice.address,
    timeout: 1200000
  }
);

// Verify attestation
const paymentMethod = client.getPaymentMethod();
const result = await contract.methods.verify_comm(
  parsed.publicKeyX,
  parsed.publicKeyY,
  parsed.hash,
  parsed.signature,
  parsed.requestUrls,
  parsed.allowedUrls,
  parsed.commitments,
  parsed.randomScalars,
  parsed.msgsChunks,
  parsed.msgs,
  H,
  parsed.id
).send({ 
  from: alice.address, 
  fee: { paymentMethod } 
}).wait({ timeout: 180000 });

// Check for success event
if (result.status === 'success') {
  const events = await ContractHelpers.getSuccessEvents(
    client.getNode(),
    BusinessProgramContract.events.SuccessEvent,
    result.blockNumber!
  );
  console.log('Event emitted:', events.length > 0);
}

await client.cleanup();
```

### Step 5: Run Local Sandbox

```bash
# Start local sandbox
PXE_PROVER_ENABLED=1 aztec start --local-network

# In another terminal, run local test
cd examples/js_test
yarn start:local
```

## Business Logic Integration

### Adding Custom Verification

In the `verify_comm` or `verify_hash` function, add your business logic after attestation verification:

```noir
// Example: Extract and verify specific field from msgs
fn verify_comm(/* ... */) -> bool {
    let allowed_url_matches_hashes = verify_attestation_comm(/* ... */);
    
    // Parse msgs to extract JSON field
    let balance = parse_json_field(msgs, "balance");
    
    // Verify condition
    assert(balance > 1000);
    
    // Emit event
    BusinessProgram::at(self.address)
        .check_values_emit_event(/* ... */)
        .enqueue(self.context);
    
    true
}
```

### Using JSON Parser

The template includes a JSON parser dependency:

```noir
use json_parser::parse_field;

// Extract field from JSON message
let value = parse_field(msgs, "data.balance");
assert(value == expected_value);
```

## Contract Storage

| Field | Type | Description |
|-------|------|-------------|
| `admin` | `Address` | Address that can update allowed URLs |
| `allowed_url_hashes` | `[Field; 3]` | Hashes of allowed URLs (not full URLs to save space) |
| `H` | `EmbeddedCurvePoint` | Point H for commitment verification (omit for hash-only) |

## Verification Functions

### verify_attestation_comm

1. Verifies EIP712 signature
2. Verifies `request_url` is the start of one of `allowed_urls`
   - Obtains index of matching allowed_url (unconstrained)
   - Verifies allowed_url is indeed the start of request_url
3. Hashes the matched allowed_url (output)
4. Verifies commitments: `coms[i] == msgs_chunks[i]*G + rnds[i]*H`

### verify_attestation_hashing

1. Verifies EIP712 signature
2. Verifies `request_url` is the start of one of `allowed_urls`
3. Hashes the matched allowed_url (output)
4. Verifies hashes: `data_hashes[i] == sha256(plain_json_response_contents[i])`

## Public Event Emission

Both verification functions are **private** and call a **public** function at the end. The public function:
- Checks `allowed_url_matches_hashes` against public storage
- Checks point `H` against public storage
- Enqueues the event for later execution

**Full verification is confirmed only when the public event is emitted**, after all private and public checks have passed.

## Benchmarks

**Environment:** MacBook Air M2 (8-core, 3.49 GHz, 16GB RAM)

| Method | Time (ms) | Circuit Size |
|--------|-----------|--------------|
| Commitment-based (65 comms) | 41,113 | 711,763 constraints |
| Commitment-based (small) | 36,538 | 321,513 constraints |
| Hash-based | 42,784 | 794,646 constraints |

**Note:** These benchmarks include end-to-end transaction submission and blockchain interaction, not just proving time. Typical zkVM benchmarks focus on proving time in isolation.

## Troubleshooting

### Common Issues

1. **Compilation fails**
   - Ensure Aztec Sandbox version is `3.0.0-devnet.6-patch.1`
   - Check Noir syntax is up to date

2. **Deployment timeout**
   - Increase timeout in `deployContract` call
   - Check devnet status

3. **Verification fails**
   - Verify attestation signature is valid
   - Check URL matching (request_url must start with allowed_url)
   - Ensure H point matches contract storage

4. **Event not emitted**
   - Check public function execution
   - Verify all private checks passed
   - Check blockchain confirmation

## Resources

- [Aztec Network Documentation](https://docs.aztec.network)
- [Noir Language Guide](https://noir-lang.org)
- [zkTLS Verification Noir Repository](https://github.com/primus-labs/zktls-verification-noir)
- [Example Contracts](../examples/aztec-commitment-verify/)
