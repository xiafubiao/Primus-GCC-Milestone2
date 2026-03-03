# Attestation Verifier Parsing Library

TypeScript library for parsing Primus attestation JSON into Aztec smart contract inputs.

## Installation

```bash
cd src/platforms/aztec/att_verifier_parsing
yarn install
yarn build
```

## Usage

### Parse Commitment-based Attestation

```typescript
import { parseCommitmentAttestation } from './index.js';
import * as fs from 'fs';

const attestationData = JSON.parse(fs.readFileSync('attestation.json', 'utf-8'));

const parsed = parseCommitmentAttestation(attestationData, {
  maxResponseNum: 10,
  allowedUrls: [
    'https://api.example.com/data',
    'https://api.example.com/info',
    'https://api.example.com/status'
  ],
  grumpkinBatchSize: 65,
});

// Parsed output:
// {
//   publicKeyX: number[],
//   publicKeyY: number[],
//   hash: number[],
//   signature: number[],
//   requestUrls: number[][],
//   allowedUrls: number[][],
//   commitments: Point[],
//   randomScalars: bigint[],
//   msgsChunks: bigint[],
//   msgs: number[],
//   id: number
// }
```

### Parse Hashing-based Attestation

```typescript
import { parseHashingAttestation } from './index.js';

const parsed = parseHashingAttestation(attestationData, {
  maxResponseNum: 10,
  allowedUrls: [/* ... */],
});

// Parsed output:
// {
//   publicKeyX: number[],
//   publicKeyY: number[],
//   hash: number[],
//   signature: number[],
//   requestUrls: number[][],
//   allowedUrls: number[][],
//   dataHashes: number[][],
//   plainJsonResponses: number[][],
//   id: number
// }
```

## Key Functions

### `computeMsgsChunks(jsonResponse, batchSize)`

Splits a JSON response string into field element chunks using bit packing.

```typescript
const chunks = computeMsgsChunks(
  '{"balance": 1000, "status": "active"}',
  65  // batch size
);
// Returns: bigint[] - field elements for commitment verification
```

### `parseCommitments(verificationArray)`

Parses hex-encoded commitment points.

```typescript
const commitments = parseCommitments([
  '04abc123...',  // 65-byte uncompressed EC point
  '04def456...',
]);
// Returns: Point[] - { x: bigint, y: bigint, is_infinite: false }
```

### `parseRandomScalars(randomHexArray)`

Parses hex-encoded random scalars.

```typescript
const scalars = parseRandomScalars([
  '0x123abc...',
  '0x456def...',
]);
// Returns: bigint[]
```

## Data Structures

### `Point`

```typescript
interface Point {
  x: bigint;
  y: bigint;
  is_infinite: boolean;
}
```

### `ParseConfig`

```typescript
interface ParseConfig {
  maxResponseNum: number;
  allowedUrls: string[];
  grumpkinBatchSize?: number;  // For commitment-based
}
```

## Implementation Details

### Bytes to Scalar Conversion

The library converts 32-byte arrays to field scalars using the same algorithm as the Rust implementation:

1. Split bytes into 4 limbs of 8 bytes each
2. Convert each limb to bigint (big-endian)
3. Combine limbs with 64-bit shifts

### Bit Packing for Commitments

For commitment-based attestations, the JSON response is converted to field elements:

1. Encode JSON string to UTF-8 bytes
2. Reverse byte order
3. Convert to bit array
4. Pack bits into field elements using powers of 2

This matches the `split_json_response` function in the Rust implementation.

## Files

- `src/index.ts` - Main exports
- `src/types.ts` - TypeScript type definitions
- `src/commitment.ts` - Commitment utilities
- `src/utils.ts` - Helper functions

## Dependencies

- Node.js >= 18
- TypeScript >= 5.0

## License

MIT
