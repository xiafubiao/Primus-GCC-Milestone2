use dep::aztec::macros::aztec;

/**
 * Aztec Smart Contract Template for Primus zkTLS Attestation Verification
 * 
 * This contract template provides a complete implementation for verifying
 * Primus zkTLS attestations. Developers should add their custom business
 * logic checks in the verify_comm and verify_hash functions.
 * 
 * Features:
 * - Supports commitment-based attestations (Grumpkin curve)
 * - Supports hashing-based attestations (SHA256)
 * - Admin-controlled allowed URL management
 * - Public event emission upon successful verification
 * 
 * Usage:
 * 1. Add your business logic checks in verify_comm or verify_hash
 * 2. Compile: aztec-nargo compile
 * 3. Generate bindings: aztec codegen -o src/artifacts target
 * 4. Deploy using aztec-attestation-sdk
 * 
 * Note: Point H is only needed for commitment-based attestations.
 *       For hash-only contracts, you can remove H-related code.
 */
#[aztec]
pub contract BusinessProgram {
    use att_verifier_lib::{verify_attestation_comm, verify_attestation_hashing};
    use aztec::macros::{events::event, functions::{external, initializer}};
    use aztec::macros::storage::storage;
    use aztec::protocol_types::address::AztecAddress;
    use aztec::state_vars::{public_immutable::PublicImmutable, public_mutable::PublicMutable};
    use std::embedded_curve_ops::EmbeddedCurvePoint;

    // Global constants
    global MAX_URL_LEN: u32 = 1024;      // Maximum URL length
    global MAX_MSGS_LEN: u32 = 2054;     // Maximum message length for commitment-based
    global MAX_CONTENT_LEN: u32 = 1000;  // Maximum content length for hash-based
    global MAX_COMMS: u32 = 65;          // Maximum number of commitments

    /**
     * Event emitted upon successful attestation verification
     */
    #[event]
    struct SuccessEvent {
        sender: AztecAddress,
        contract_address: AztecAddress,
        id: Field,
    }

    /**
     * Contract storage
     */
    #[storage]
    struct Storage<Context> {
        // Admin address that can update allowed_url_hashes
        admin: PublicMutable<AztecAddress, Context>,
        // Hashes of allowed URLs (storing complete URLs is too expensive)
        allowed_url_hashes: PublicMutable<[Field; 3], Context>,
        // Point H used in commitment verification (only for commitment-based)
        H: PublicImmutable<EmbeddedCurvePoint, Context>,
    }

    /**
     * Set new admin address (only callable by current admin)
     */
    #[external("public")]
    fn set_admin(new_admin: AztecAddress) {
        assert(
            self.storage.admin.read().eq(self.msg_sender().unwrap()),
            "caller is not admin"
        );
        self.storage.admin.write(new_admin);
    }

    /**
     * Contract constructor
     * 
     * @param admin - Admin address
     * @param allowed_url_hashes - Poseidon2 hashes of allowed URLs
     * @param H - Grumpkin curve point H (only for commitment-based)
     */
    #[initializer]
    #[external("public")]
    fn constructor(
        admin: AztecAddress,
        allowed_url_hashes: [Field; 3],
        H: EmbeddedCurvePoint
    ) {
        assert(!admin.is_zero(), "invalid admin");
        self.storage.admin.write(admin);
        self.storage.allowed_url_hashes.write(allowed_url_hashes);
        self.storage.H.initialize(H);
    }

    /**
     * Update allowed URL hashes (only callable by admin)
     */
    #[external("public")]
    fn update_allowed_url_hashes(allowed_url_hashes: [Field; 3]) {
        assert(
            self.storage.admin.read().eq(self.msg_sender().unwrap()),
            "caller is not admin"
        );
        self.storage.allowed_url_hashes.write(allowed_url_hashes);
    }

    /**
     * Check URL hashes and H point against storage, then emit success event.
     * Used for commitment-based verification.
     */
    #[external("public")]
    fn check_values_emit_event(
        sender: AztecAddress,
        contract_address: AztecAddress,
        id: Field,
        allowed_url_matches_hashes: [Field; 2],
        H: EmbeddedCurvePoint,
    ) {
        // Verify allowed_url_matches_hashes are in storage
        let allowed_url_hashes: [Field; 3] = self.storage.allowed_url_hashes.read();
        for i in 0..2 {
            let check_hash = allowed_url_matches_hashes[i];
            let mut found = false;
            for j in 0..3 {
                if allowed_url_hashes[j] == check_hash {
                    found = true;
                }
            }
            assert(found, "URL hash not in allowed list");
        }

        // Verify H matches stored value
        let stored_H: EmbeddedCurvePoint = self.storage.H.read();
        assert(H == stored_H, "H point mismatch");

        // Emit success event
        self.emit(SuccessEvent { sender, contract_address, id });
    }

    /**
     * Check URL hashes against storage, then emit success event.
     * Used for hash-based verification (no H point check).
     */
    #[external("public")]
    fn check_urls_emit_event(
        sender: AztecAddress,
        contract_address: AztecAddress,
        id: Field,
        allowed_url_matches_hashes: [Field; 2],
    ) {
        // Verify allowed_url_matches_hashes are in storage
        let allowed_url_hashes: [Field; 3] = self.storage.allowed_url_hashes.read();
        for i in 0..2 {
            let check_hash = allowed_url_matches_hashes[i];
            let mut found = false;
            for j in 0..3 {
                if allowed_url_hashes[j] == check_hash {
                    found = true;
                }
            }
            assert(found, "URL hash not in allowed list");
        }

        // Emit success event
        self.emit(SuccessEvent { sender, contract_address, id });
    }

    /**
     * Verify a commitment-based Primus attestation.
     * 
     * This function:
     * 1. Calls verify_attestation_comm to verify the attestation
     * 2. Adds custom business logic checks on msgs (TODO)
     * 3. Emits a public success event
     * 
     * @return true if verification succeeds
     * 
     * Circuit size: ~711k constraints (65 commitments)
     */
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
        // Step 1: Verify the attestation signature, URLs, and commitments
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

        // ============================================================
        // TODO: INSERT YOUR BUSINESS LOGIC CHECKS HERE
        // ============================================================
        // Example: Parse msgs as JSON and verify specific fields
        // let json = JSON2055::parse_bounded_vec_json(msgs);
        // let balance = json.get_number("balance").unwrap();
        // assert(balance > 1000, "Balance too low");
        // ============================================================

        // Step 2: Emit public success event (enqueued for later execution)
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

    /**
     * Verify a hashing-based Primus attestation.
     * 
     * This function:
     * 1. Calls verify_attestation_hashing to verify the attestation
     * 2. Adds custom business logic checks on plain_json_response_contents (TODO)
     * 3. Emits a public success event
     * 
     * @return true if verification succeeds
     * 
     * Circuit size: ~794k constraints
     */
    #[external("private")]
    fn verify_hash(
        public_key_x: [u8; 32],
        public_key_y: [u8; 32],
        hash: [u8; 32],
        signature: [u8; 64],
        request_urls: [BoundedVec<u8, MAX_URL_LEN>; 2],
        allowed_urls: [BoundedVec<u8, MAX_URL_LEN>; 3],
        data_hashes: [[u8; 32]; 2],
        plain_json_response_contents: [BoundedVec<u8, MAX_CONTENT_LEN>; 2],
        id: Field,
    ) -> bool {
        // Step 1: Verify the attestation signature, URLs, and response hashes
        let allowed_url_matches_hashes: [Field; 2] = verify_attestation_hashing(
            public_key_x,
            public_key_y,
            hash,
            signature,
            request_urls,
            allowed_urls,
            data_hashes,
            plain_json_response_contents,
        );

        // ============================================================
        // TODO: INSERT YOUR BUSINESS LOGIC CHECKS HERE
        // ============================================================
        // Example: Parse JSON and verify specific fields
        // for i in 0..2 {
        //     let json = JSON2kb::parse_bounded_vec_json(plain_json_response_contents[i]);
        //     let status = json.get_string("status").unwrap();
        //     assert(status == "active", "Status not active");
        // }
        // ============================================================

        // Step 2: Emit public success event (enqueued for later execution)
        BusinessProgram::at(self.address)
            .check_urls_emit_event(
                self.msg_sender().unwrap(),
                self.address,
                id,
                allowed_url_matches_hashes,
            )
            .enqueue(self.context);

        true
    }
}
