use dep::poseidon::poseidon2::Poseidon2;
use sha256::sha256_var;
use std::embedded_curve_ops::{
    embedded_curve_add, EmbeddedCurvePoint, EmbeddedCurveScalar, fixed_base_scalar_mul,
    multi_scalar_mul,
};
use string_search::{StringBody, StringBody1024, SubString, SubString1024};

/// Maximum URL length in bytes
global MAX_URL_LEN: u32 = 1024;

/// Maximum content length for hash-based verification
global MAX_CONTENT_LEN: u32 = 1000;

/// Verifies a commitment-based Primus zkTLS attestation.
/// 
/// # Parameters
/// - `public_key_x`, `public_key_y`: Attestor's public key (secp256k1)
/// - `hash`: Message hash that was signed
/// - `signature`: ECDSA signature (64 bytes)
/// - `request_urls`: URLs that were requested (max 2)
/// - `allowed_urls`: Pre-approved URLs (max 3)
/// - `coms`: Pedersen commitments to message chunks
/// - `rnds`: Random scalars for commitments
/// - `msgs_chunks`: Message chunks as field elements
/// - `H`: Fixed Grumpkin curve point (per business case)
/// 
/// # Returns
/// Array of 2 Poseidon2 hashes of the matched allowed URLs
/// 
/// # Verification Steps
/// 1. Verify ECDSA secp256k1 signature
/// 2. Verify each request_url starts with one of the allowed_urls
/// 3. Hash the matched allowed_urls (output)
/// 4. Verify commitments: coms[i] == msgs_chunks[i]*G + rnds[i]*H
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
) -> [Field; 2] {
    // Step 1: Verify ECDSA signature
    assert(std::ecdsa_secp256k1::verify_signature(public_key_x, public_key_y, signature, hash));

    // Step 2: Verify request URLs match allowed URLs
    let mut allowed_url_matches: [Field; 2] = [0; 2];
    for i in 0..2 {
        // Get index of matching allowed_url (unconstrained search)
        let (found, url_index) = unsafe { get_allowed_url_index(request_urls[i], allowed_urls) };
        assert(found == true, "No allowed URL matches the request URL");
        
        // Verify the allowed_url is a prefix of request_url
        let request_url_haystack: StringBody1024 =
            StringBody::new(request_urls[i].storage(), request_urls[i].len());
        let allowed_url = allowed_urls[url_index];
        let needle: SubString1024 = SubString::new(allowed_url.storage(), allowed_url.len());

        let (result, match_position): (bool, u32) = request_url_haystack.substring_match(needle);

        // Match position must be 0 (prefix match)
        assert(result & (match_position == 0), "URL check failed");
        
        // Hash the matched allowed_url using Poseidon2
        let mut hash_input: [Field; 1024] = [0; 1024];
        for j in 0..1024 {
            if j < allowed_url.len() {
                hash_input[j] = allowed_url.storage()[j] as Field;
            }
        }
        // TODO: When larger storage is supported, hashing may not be needed
        // TODO: Can we hash without zero padding?
        allowed_url_matches[i] = Poseidon2::hash(hash_input, 1024);
    }

    // Step 3: Verify Pedersen commitments
    // Equation: coms[i] == msgs_chunks[i] * G + rnds[i] * H
    for i in 0..MAX_COMMS {
        if i < coms.len() {
            assert(
                embedded_curve_add(
                    fixed_base_scalar_mul(EmbeddedCurveScalar::from_field(msgs_chunks.get(i))),
                    multi_scalar_mul([H], [EmbeddedCurveScalar::from_field(rnds.get(i))]),
                )
                    == coms.get(i),
            );
        }
    }

    allowed_url_matches
}

/// Verifies a hashing-based Primus zkTLS attestation.
/// 
/// # Parameters
/// - `public_key_x`, `public_key_y`: Attestor's public key (secp256k1)
/// - `hash`: Message hash that was signed
/// - `signature`: ECDSA signature (64 bytes)
/// - `request_urls`: URLs that were requested (max 2)
/// - `allowed_urls`: Pre-approved URLs (max 3)
/// - `data_hashes`: Expected SHA256 hashes of response content
/// - `plain_json_response_contents`: Actual response content to verify
/// 
/// # Returns
/// Array of 2 Poseidon2 hashes of the matched allowed URLs
/// 
/// # Verification Steps
/// 1. Verify ECDSA secp256k1 signature
/// 2. Verify each request_url starts with one of the allowed_urls
/// 3. Hash the matched allowed_urls (output)
/// 4. Verify SHA256 hashes: data_hashes[i] == sha256(plain_json_response_contents[i])
pub fn verify_attestation_hashing(
    public_key_x: [u8; 32],
    public_key_y: [u8; 32],
    hash: [u8; 32],
    signature: [u8; 64],
    request_urls: [BoundedVec<u8, MAX_URL_LEN>; 2],
    allowed_urls: [BoundedVec<u8, MAX_URL_LEN>; 3],
    data_hashes: [[u8; 32]; 2],
    plain_json_response_contents: [BoundedVec<u8, MAX_CONTENT_LEN>; 2],
) -> [Field; 2] {
    // Step 1: Verify ECDSA signature
    assert(std::ecdsa_secp256k1::verify_signature(public_key_x, public_key_y, signature, hash));

    // Step 2: Verify request URLs match allowed URLs
    let mut allowed_url_matches: [Field; 2] = [0; 2];
    for i in 0..2 {
        let (found, url_index) = unsafe { get_allowed_url_index(request_urls[i], allowed_urls) };
        assert(found == true, "No allowed URL matches the request URL");
        
        let request_url_haystack: StringBody1024 =
            StringBody::new(request_urls[i].storage(), request_urls[i].len());
        let allowed_url = allowed_urls[url_index];
        let needle: SubString1024 = SubString::new(allowed_url.storage(), allowed_url.len());

        let (result, match_position): (bool, u32) = request_url_haystack.substring_match(needle);
        assert(result & (match_position == 0), "URL check failed");
        
        let mut hash_input: [Field; 1024] = [0; 1024];
        for j in 0..1024 {
            if j < allowed_url.len() {
                hash_input[j] = allowed_url.storage()[j] as Field;
            }
        }
        allowed_url_matches[i] = Poseidon2::hash(hash_input, 1024);
    }

    // Step 3: Verify SHA256 hashes of response content
    for i in 0..2 {
        let hash = sha256_var(
            plain_json_response_contents[i].storage(),
            plain_json_response_contents[i].len() as u64,
        );
        assert(hash == data_hashes[i]);
    }

    allowed_url_matches
}

/// Unconstrained string search function.
/// Finds the first occurrence of needle in haystack.
/// 
/// # Returns
/// (found, found_index) where found_index is the position of the match
unconstrained fn search(
    haystack: BoundedVec<u8, MAX_URL_LEN>,
    needle: BoundedVec<u8, MAX_URL_LEN>,
) -> (bool, u32) {
    let haystack_length: u32 = haystack.len();
    let needle_length: u32 = needle.len();
    assert(needle_length > 0, "needle length of size 0 not supported");
    assert(haystack_length > 0, "haystack length of size 0 not supported");
    
    let mut found = false;
    let mut found_index: u32 = 0;
    
    for i in 0..haystack_length - needle_length + 1 {
        if found == true {
            break;
        }
        for j in 0..needle_length {
            if haystack.get(i + j) != needle.get(j) {
                break;
            } else if j == needle_length - 1 {
                found = true;
            }
            if found == true {
                found_index = i;
                break;
            }
        }
    }

    (found, found_index)
}

/// Unconstrained function to find the index of an allowed URL.
/// Returns the index of the first allowed_url that is a prefix of request_url.
/// 
/// # Returns
/// (found, index) where index is the position in allowed_urls array
/// Use max u32 value (3050913689) to indicate "not found"
unconstrained fn get_allowed_url_index(
    request_url: BoundedVec<u8, MAX_URL_LEN>,
    allowed_urls: [BoundedVec<u8, MAX_URL_LEN>; 3],
) -> (bool, u32) {
    let mut found = false;
    let mut index: u32 = 3050913689; // Max u32 to indicate "not found"
    
    for i in 0..allowed_urls.len() {
        let allowed_url = allowed_urls[i];
        if allowed_url.len() <= request_url.len() {
            let (result, match_position) = search(request_url, allowed_url);
            // Only store if valid prefix match and not already found
            if result & (match_position == 0) & !found {
                found = true;
                index = i;
            }
        }
    }
    (found, index)
}
