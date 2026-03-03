/**
 * Types for Primus attestation data structures
 * Used for parsing attestation JSON into Aztec contract inputs
 */

/**
 * Attestation request information
 */
export interface AttestationRequest {
  url: string;
  header: string;
  method: string;
  body: string;
}

/**
 * Response resolve configuration for data extraction
 */
export interface ResponseResolve {
  keyName: string;
  parseType: string;
  parsePath: string;
}

/**
 * Wrapper for response resolves per URL
 */
export interface OneUrlResponseResolves {
  oneUrlResponseResolve: ResponseResolve[];
}

/**
 * Core attestation data structure
 */
export interface AttestationData {
  recipient: string;
  request: AttestationRequest | AttestationRequest[];
  responseResolves: OneUrlResponseResolves | OneUrlResponseResolves[];
  data: string;
  attConditions: string;
  timestamp: number | string;
  additionParams: string;
}

/**
 * Public data from attestation file
 */
export interface PublicData {
  attestation: AttestationData;
  signature: string;
}

/**
 * Private data from attestation file
 */
export interface PrivateData {
  random?: string[];
  content?: string;
  plain_json_response?: Array<{
    id: string;
    content: string;
  }>;
}

/**
 * Complete attestation file structure
 */
export interface AttestationFile {
  public_data: PublicData[];
  private_data: PrivateData[] | PrivateData;
}

/**
 * Grumpkin curve point (embedded curve for Aztec)
 */
export interface Point {
  x: bigint;
  y: bigint;
  is_infinite: boolean;
}

/**
 * Configuration for parsing attestations
 */
export interface ParseConfig {
  /** Maximum number of responses to handle */
  maxResponseNum: number;
  /** List of allowed URLs for verification */
  allowedUrls: string[];
  /** Batch size for Grumpkin commitments (commitment-based only) */
  grumpkinBatchSize?: number;
}

/**
 * Parsed commitment-based attestation data
 * Ready to be passed to Aztec contract's verify_comm function
 */
export interface ParsedCommitmentData {
  /** Attestor public key X coordinate (32 bytes) */
  publicKeyX: number[];
  /** Attestor public key Y coordinate (32 bytes) */
  publicKeyY: number[];
  /** Message hash that was signed (32 bytes) */
  hash: number[];
  /** ECDSA signature (64 bytes) */
  signature: number[];
  /** Request URLs (max 2, each as byte array) */
  requestUrls: number[][];
  /** Allowed URLs (max 3, each as byte array) */
  allowedUrls: number[][];
  /** Pedersen commitments (Grumpkin points) */
  commitments: Point[];
  /** Random scalars for commitments */
  randomScalars: bigint[];
  /** Message chunks as field elements */
  msgsChunks: bigint[];
  /** Message bytes for business logic verification */
  msgs: number[];
  /** Unique attestation ID */
  id: number;
  /** Original attestation data (for reference) */
  attestationData: any;
}

/**
 * Parsed hashing-based attestation data
 * Ready to be passed to Aztec contract's verify_hash function
 */
export interface ParsedHashingData {
  /** Attestor public key X coordinate (32 bytes) */
  publicKeyX: number[];
  /** Attestor public key Y coordinate (32 bytes) */
  publicKeyY: number[];
  /** Message hash that was signed (32 bytes) */
  hash: number[];
  /** ECDSA signature (64 bytes) */
  signature: number[];
  /** Request URLs (max 2, each as byte array) */
  requestUrls: number[][];
  /** Allowed URLs (max 3, each as byte array) */
  allowedUrls: number[][];
  /** Expected SHA256 hashes of response content (max 2, each 32 bytes) */
  dataHashes: number[][];
  /** Actual response content to verify (max 2, each as byte array) */
  plainJsonResponses: number[][];
  /** Unique attestation ID */
  id: number;
  /** Original attestation data (for reference) */
  attestationData: any;
}

/**
 * EIP712 signature components
 */
export interface EIP712Signature {
  v: number;
  r: string;
  s: string;
}

/**
 * EIP712 domain separator
 */
export interface EIP712Domain {
  name: string;
  version: string;
  chainId: string;
  verifyingContract: string;
  salt?: string | null;
}

/**
 * Complete EIP712 typed data structure
 */
export interface EIP712TypedData {
  types: Record<string, { name: string; type: string }[]>;
  primaryType: string;
  domain: EIP712Domain;
  message: {
    schema: string;
    recipient: string;
    expirationTime: number;
    revocable: boolean;
    refUID: string;
    data: string;
    deadline: number;
  };
  signature?: EIP712Signature;
}
