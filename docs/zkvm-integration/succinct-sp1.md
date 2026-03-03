# Succinct SP1 Integration Guide

## Overview

This guide covers integrating Primus zkTLS attestations with Succinct's SP1 zkVM platform. SP1 is a high-performance, EVM-compatible zkVM that executes standard Rust programs.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Dapp Application                         │
└─────────────────────────────────────────────────────────────┘
                           │
                           │ Attestation + Plain Response
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                   SP1 Verification Program                  │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  1. Verify EIP712 Signature                           │  │
│  │  2. Validate URL & Response                           │  │
│  │  3. Extract JSON Fields                               │  │
│  │  4. Execute Business Logic                            │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                           │
                           │ SP1 Proof
                           ▼
┌─────────────────────────────────────────────────────────────┐
│                    On-Chain Verifier                        │
└─────────────────────────────────────────────────────────────┘
```

## Components

### 1. SP1 Verifier Program

**Location:** `src/platforms/succinct/sp1_verifier/`

A Rust program that runs inside the SP1 zkVM.

**Project Structure:**

```
sp1_verifier/
├── Cargo.toml
├── src/
│   ├── main.rs              # Entry point
│   ├── attestation.rs       # Attestation parsing & verification
│   ├── signature.rs         # EIP712 signature verification
│   ├── crypto/
│   │   ├── ecdsa.rs         # ECDSA verification
│   │   └── sha256.rs        # Hash utilities
│   └── business/
│       └── logic.rs         # Custom business logic
└── tests/
    └── integration_test.rs
```

### 2. Core Verification Logic

```rust
// src/main.rs
use sp1_zkvm::{io, lib::verify::verify_sp1_proof};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct AttestationInput {
    pub attestation_json: String,
    pub plain_response: String,
    pub allowed_urls: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct VerificationResult {
    pub success: bool,
    pub extracted_data: serde_json::Value,
    pub timestamp: u64,
}

fn main() {
    // Read inputs
    let input: AttestationInput = io::read();
    
    // Parse attestation
    let attestation: AttestationData = serde_json::from_str(&input.attestation_json)
        .expect("Failed to parse attestation");
    
    // Step 1: Verify EIP712 signature
    let signature_valid = verify_eip712_signature(&attestation);
    assert!(signature_valid, "Invalid signature");
    
    // Step 2: Verify URL matches allowed URLs
    let url_matches = verify_url(&attestation.request.url, &input.allowed_urls);
    assert!(url_matches, "URL not allowed");
    
    // Step 3: Verify response integrity
    let response_valid = verify_response_integrity(&attestation, &input.plain_response);
    assert!(response_valid, "Response integrity check failed");
    
    // Step 4: Extract required fields
    let extracted_data = extract_json_fields(&input.plain_response, &attestation.response_resolve);
    
    // Step 5: Execute business logic
    let business_result = execute_business_logic(&extracted_data);
    assert!(business_result, "Business logic check failed");
    
    // Write output
    let result = VerificationResult {
        success: true,
        extracted_data,
        timestamp: attestation.attestation.timestamp,
    };
    io::commit(&result);
}
```

### 3. EIP712 Signature Verification

```rust
// src/signature.rs
use k256::{ecdsa::VerifyingKey, RecoverableSignature};
use alloy_primitives::{Address, B256};
use sha3::Keccak256;
use sha2::Sha256;

pub struct EIP712Domain {
    pub name: String,
    pub version: String,
    pub chain_id: u64,
    pub verifying_contract: Address,
}

pub struct AttestationType {
    pub schema: B256,
    pub recipient: Address,
    pub expiration_time: u64,
    pub revocable: bool,
    pub ref_uid: B256,
    pub data: Vec<u8>,
    pub deadline: u64,
}

pub fn verify_eip712_signature(attestation: &AttestationData) -> bool {
    // Reconstruct EIP712 domain separator
    let domain_separator = compute_domain_separator(&attestation.domain);
    
    // Hash the attestation message
    let message_hash = hash_attestation_message(&attestation.message);
    
    // Combine domain separator and message hash
    let digest = Keccak256::new()
        .chain_update("\x19\x01")
        .chain_update(domain_separator)
        .chain_update(message_hash)
        .finalize();
    
    // Recover public key from signature
    let signature = RecoverableSignature::new(
        attestation.signature.r,
        attestation.signature.s,
        attestation.signature.v,
    ).expect("Invalid signature format");
    
    let recovered_key = signature
        .recover_verifying_key_from_digest(digest)
        .expect("Failed to recover key");
    
    // Verify against attestor address
    let recovered_address = public_key_to_address(&recovered_key);
    recovered_address == attestation.attestor
}

fn compute_domain_separator(domain: &EIP712Domain) -> B256 {
    Keccak256::new()
        .chain_update(
            keccak256(b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
        )
        .chain_update(keccak256(domain.name.as_bytes()))
        .chain_update(keccak256(domain.version.as_bytes()))
        .chain_update(domain.chain_id.to_be_bytes())
        .chain_update(domain.verifying_contract.0)
        .finalize()
        .into()
}
```

### 4. Response Integrity Verification

```rust
// src/attestation.rs
use sha2::{Sha256, Digest};

pub fn verify_response_integrity(
    attestation: &AttestationData,
    plain_response: &str,
) -> bool {
    match attestation.attestation_type.as_str() {
        "commitment" => verify_commitment_integrity(attestation, plain_response),
        "hash" => verify_hash_integrity(attestation, plain_response),
        _ => false,
    }
}

fn verify_hash_integrity(attestation: &AttestationData, plain_response: &str) -> bool {
    // For hash-based attestation, verify SHA256 hashes match
    let response_hash = Sha256::digest(plain_response.as_bytes());
    
    let stored_hash = &attestation.attestation.data_hash;
    response_hash.as_slice() == stored_hash
}

fn verify_commitment_integrity(
    attestation: &AttestationData,
    plain_response: &str,
) -> bool {
    // For commitment-based attestation, verify Grumpkin curve commitments
    // coms[i] == msgs_chunks[i] * G + rnds[i] * H
    
    let commitments = &attestation.attestation.commitments;
    let msgs_chunks = &attestation.attestation.msgs_chunks;
    let random_scalars = &attestation.attestation.random_scalars;
    
    for i in 0..commitments.len() {
        let expected = grumpkin_multiply_add(
            &msgs_chunks[i],
            &GRUMPKIN_GENERATOR_G,
            &random_scalars[i],
            &attestation.attestation.point_h,
        );
        
        if commitments[i] != expected {
            return false;
        }
    }
    
    true
}
```

### 5. JSON Field Extraction

```rust
// src/business/logic.rs
use serde_json::Value;
use jsonpath_rust::JsonPath;

pub fn extract_json_fields(
    response: &str,
    resolve_paths: &[ResponseResolve],
) -> Value {
    let json: Value = serde_json::from_str(response)
        .expect("Invalid JSON response");
    
    let mut result = serde_json::Map::new();
    
    for resolve in resolve_paths {
        let path = JsonPath::parse(&resolve.parse_path)
            .expect("Invalid JSON path");
        
        let value = path.find(&json);
        result.insert(resolve.key_name.clone(), value);
    }
    
    Value::Object(result)
}

pub fn execute_business_logic(extracted_data: &Value) -> bool {
    // Example: Verify balance is above threshold
    if let Some(balance) = extracted_data.get("balance").and_then(|v| v.as_u64()) {
        return balance > 1000;
    }
    
    // Example: Verify status is "active"
    if let Some(status) = extracted_data.get("status").and_then(|v| v.as_str()) {
        return status == "active";
    }
    
    false
}
```

## Building and Running

### Prerequisites

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup install stable

# Install SP1 toolchain
curl -L https://sp1.succinct.xyz | bash
sp1up
```

### Build the Verifier Program

```bash
cd src/platforms/succinct/sp1_verifier

# Build for SP1
cargo build --release

# Generate ELF binary
sp1-elf build --release
```

### Generate Proof

```rust
// tests/integration_test.rs
use sp1_sdk::{ProverClient, SP1Stdin, SP1ProofWithPublicValues};

#[test]
fn test_attestation_verification() {
    // Initialize prover client
    let client = ProverClient::new();
    
    // Load ELF binary
    let elf = include_bytes!("../../elf/riscv32im-succinct-zkvm-elf");
    
    // Prepare inputs
    let mut stdin = SP1Stdin::new();
    stdin.write(&AttestationInput {
        attestation_json: read_fixture("attestation.json"),
        plain_response: read_fixture("response.json"),
        allowed_urls: vec![
            "https://api.example.com/data".to_string(),
        ],
    });
    
    // Generate proof
    let (proof, public_values) = client
        .prove(elf, stdin)
        .run()
        .expect("Proving failed");
    
    // Verify proof
    client.verify(&proof, elf).expect("Verification failed");
    
    // Read output
    let result: VerificationResult = public_values.read();
    assert!(result.success);
    
    println!("Proof generated successfully!");
    println!("Extracted data: {:?}", result.extracted_data);
}
```

### Deploy On-Chain Verifier

```rust
// Deploy to Ethereum/BSC
use sp1_sdk::SP1VerifyingKey;

// Get verifying key
let vk = client.get_verifying_key(elf);

// Deploy verifier contract (using Foundry or Hardhat)
// The verifier contract address is derived from the VK
let verifier_address = deploy_sp1_verifier(&vk);

// Submit proof on-chain
verifier_contract
    .verify_proof(&proof, &public_values)
    .send()
    .await?;
```

## Integration with Primus Network

### Complete Workflow

```rust
// Full integration example
use primus_sdk::PrimusClient;
use sp1_sdk::{ProverClient, SP1Stdin};

async fn verify_with_sp1(
    primus_client: &PrimusClient,
    task_id: &str,
    allowed_urls: Vec<String>,
) -> Result<VerificationResult> {
    // Step 1: Get attestation from Primus Network
    let attestation = primus_client.get_attestation(task_id).await?;
    
    // Step 2: Extract plain response locally
    let plain_response = primus_sdk::extract_plain_response(&attestation)?;
    
    // Step 3: Prepare SP1 inputs
    let input = AttestationInput {
        attestation_json: serde_json::to_string(&attestation)?,
        plain_response,
        allowed_urls,
    };
    
    // Step 4: Generate SP1 proof
    let client = ProverClient::new();
    let elf = include_bytes!("../../elf/riscv32im-succinct-zkvm-elf");
    
    let mut stdin = SP1Stdin::new();
    stdin.write(&input);
    
    let (proof, public_values) = client.prove(elf, stdin).run()?;
    
    // Step 5: Verify and return result
    client.verify(&proof, elf)?;
    let result: VerificationResult = public_values.read();
    
    Ok(result)
}
```

## Performance Optimization

### Circuit Optimization Techniques

1. **Batch Verification**
   ```rust
   // Verify multiple attestations in single proof
   pub fn batch_verify(attestations: &[AttestationInput]) -> Vec<VerificationResult> {
       attestations.iter().map(verify_single).collect()
   }
   ```

2. **Efficient Hashing**
   ```rust
   // Use SP1's native SHA256 implementation
   use sp1_zkvm::lib::sha::sha256;
   
   let hash = sha256(&data);
   ```

3. **Constraint Reduction**
   - Minimize branching in verification logic
   - Use fixed-size arrays where possible
   - Pre-compute constants outside the circuit

### Benchmarking

```rust
#[test]
fn benchmark_verification() {
    let start = std::time::Instant::now();
    
    // Generate proof
    let (proof, _) = client.prove(elf, stdin).run().unwrap();
    
    let prove_time = start.elapsed();
    println!("Proving time: {:?}", prove_time);
    
    let start = std::time::Instant::now();
    
    // Verify proof
    client.verify(&proof, elf).unwrap();
    
    let verify_time = start.elapsed();
    println!("Verification time: {:?}", verify_time);
}
```

**Target Performance:**
- Proving time: < 30s for typical attestation
- Verification time: < 1s (on-chain)
- Proof size: < 100KB

## Comparison with Other zkVMs

| Feature | SP1 | Aztec Noir | Brevis Pico |
|---------|-----|------------|-------------|
| Language | Rust | Noir DSL | Rust |
| EVM Compatible | ✅ | ✅ (Aztec EVM) | ✅ |
| Proving Time | Fast | Medium | Fast |
| Proof Size | ~100KB | ~50KB | ~20KB |
| Tooling Maturity | High | Medium | Medium |
| Best For | General purpose | Aztec ecosystem | Mobile/edge |

## Resources

- [SP1 Documentation](https://docs.succinct.xyz)
- [SP1 GitHub](https://github.com/succinctlabs/sp1)
- [Primus Network Docs](https://docs.primuslabs.xyz)
- [Example Implementation](../examples/end-to-end-demo/)

## Next Steps

1. Implement core SP1 verifier program
2. Add comprehensive test suite
3. Optimize for common use cases
4. Deploy on-chain verifier contract
5. Integrate with Primus SDK
