# Primus Attestation Verifier Library (Noir)

Core Noir library for verifying Primus zkTLS attestations in Aztec smart contracts.

## Overview

This library provides two main verification functions:

1. **`verify_attestation_comm`** - Verifies commitment-based attestations (Grumpkin curve)
2. **`verify_attestation_hashing`** - Verifies hashing-based attestations (SHA256)

## Functions

### `verify_attestation_comm`

Verifies a commitment-based Primus attestation.

```noir
pub fn verify_attestation_comm<let MAX_COMMS: u32>(
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
) -> [Field; 2]
```

**Verification Steps:**
1. Verify ECDSA secp256k1 signature
2. Verify each request_url starts with one of the allowed_urls
3. Hash the matched allowed_urls (output)
4. Verify commitments: `coms[i] == msgs_chunks[i]*G + rnds[i]*H`

**Returns:** `[Field; 2]` - Poseidon2 hashes of the matched allowed URLs

### `verify_attestation_hashing`

Verifies a hashing-based Primus attestation.

```noir
pub fn verify_attestation_hashing(
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    hash: [u8; 32],
    signature: [u8; 64],
    request_urls: [BoundedVec<u8, MAX_URL_LEN>; 2],
    allowed_urls: [BoundedVec<u8, MAX_URL_LEN>; 3],
    data_hashes: [[u8; 32]; 2],
    plain_json_response_contents: [BoundedVec<u8, MAX_CONTENT_LEN>; 2],
) -> [Field; 2]
```

**Verification Steps:**
1. Verify ECDSA secp256k1 signature
2. Verify each request_url starts with one of the allowed_urls
3. Hash the matched allowed_urls (output)
4. Verify SHA256 hashes: `data_hashes[i] == sha256(plain_json_response_contents[i])`

**Returns:** `[Field; 2]` - Poseidon2 hashes of the matched allowed URLs

## Global Constants

```noir
global MAX_URL_LEN: u32 = 1024;       // Maximum URL length
global MAX_CONTENT_LEN: u32 = 1000;   // Maximum response content length
global MAX_COMMS: u32 = 65;           // Maximum number of commitments
```

## Dependencies

- `dep::poseidon::poseidon2::Poseidon2` - Poseidon2 hashing
- `sha256::sha256_var` - SHA256 hashing
- `std::embedded_curve_ops` - Grumpkin curve operations
- `std::ecdsa_secp256k1` - ECDSA signature verification
- `string_search` - URL string matching

## Usage

Import in your Noir contract:

```noir
use att_verifier_lib::{verify_attestation_comm, verify_attestation_hashing};
```

Then call from your verification function:

```noir
#[external("private")]
fn verify_comm(/* ... */) -> bool {
    let allowed_url_matches_hashes = verify_attestation_comm(
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
    
    // Add your business logic checks here
    
    true
}
```

## Circuit Size

| Function | Constraints |
|----------|-------------|
| `verify_attestation_comm` (65 comms) | ~711k |
| `verify_attestation_comm` (small) | ~321k |
| `verify_attestation_hashing` | ~794k |

## Notes

- Point `G` is the fixed Grumpkin generator
- Point `H` is fixed per business case (stored in contract)
- URL matching uses unconstrained search followed by constrained verification
- Poseidon2 hashing is used for URL hashes (more efficient than SHA256 in-circuit)
