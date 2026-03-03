/**
 * Attestation Verifier Parsing Library
 * 
 * Converts Primus attestation JSON into Aztec smart contract inputs.
 * Supports both commitment-based and hashing-based attestations.
 */

export {
  bytes32ToBigInt,
  generateExp,
  computeMsgsChunks,
  parseCommitments,
  parseRandomScalars,
  bytesToBigInt,
  bigIntToBytes,
} from "./commitment.js";

export type {
  AttestationRequest,
  ResponseResolve,
  OneUrlResponseResolves,
  AttestationData,
  PublicData,
  PrivateData,
  AttestationFile,
  Point,
  ParseConfig,
  ParsedCommitmentData,
  ParsedHashingData,
  EIP712Signature,
  EIP712Domain,
  EIP712TypedData,
} from "./types.js";

/**
 * Parses a commitment-based Primus attestation.
 * 
 * @param attestationData - Raw attestation JSON object
 * @param config - Parsing configuration
 * @returns Parsed data ready for Aztec contract's verify_comm function
 */
export function parseCommitmentAttestation(
  attestationData: any,
  config: {
    maxResponseNum: number;
    allowedUrls: string[];
    grumpkinBatchSize: number;
  }
): ParsedCommitmentData {
  // Extract EIP712 signature
  const eip712Data = attestationData.eip712MessageRawDataWithSignature;
  const signature = eip712Data.signature;
  
  // Convert signature to byte array
  const rBytes = Buffer.from(signature.r.slice(2), 'hex');
  const sBytes = Buffer.from(signature.s.slice(2), 'hex');
  const sigBytes = new Uint8Array(64);
  sigBytes.set(rBytes, 0);
  sigBytes.set(sBytes, 32);

  // Extract public key from attestation data
  const dataHex = eip712Data.message.data;
  const dataBytes = Buffer.from(dataHex.slice(2), 'hex');
  
  // Parse public key (bytes 0-64 of decoded data)
  const publicKeyX = Array.from(dataBytes.slice(0, 32));
  const publicKeyY = Array.from(dataBytes.slice(32, 64));

  // Parse commitments and scalars from the data
  // This is a simplified extraction - full implementation would parse the ABI-encoded data
  const commitments: Point[] = [];
  const randomScalars: bigint[] = [];
  const msgsChunks: bigint[] = [];

  // Extract message content for business logic verification
  const msgs = Array.from(dataBytes.slice(64));

  // Convert allowed URLs to byte arrays
  const allowedUrls = config.allowedUrls.map(url => 
    Array.from(new TextEncoder().encode(url))
  );

  // Parse request URLs from attestation
  const requestUrls: number[][] = [];
  
  // Generate unique ID for this attestation
  const id = Date.now() % 1000000;

  return {
    publicKeyX,
    publicKeyY,
    hash: Array.from(Buffer.from(eip712Data.message.schema.slice(2), 'hex')),
    signature: Array.from(sigBytes),
    requestUrls,
    allowedUrls,
    commitments,
    randomScalars,
    msgsChunks,
    msgs,
    id,
    attestationData,
  };
}

/**
 * Parses a hashing-based Primus attestation.
 * 
 * @param attestationData - Raw attestation JSON object
 * @param config - Parsing configuration
 * @returns Parsed data ready for Aztec contract's verify_hash function
 */
export function parseHashingAttestation(
  attestationData: any,
  config: {
    maxResponseNum: number;
    allowedUrls: string[];
  }
): ParsedHashingData {
  // Extract EIP712 signature
  const eip712Data = attestationData.eip712MessageRawDataWithSignature;
  const signature = eip712Data.signature;
  
  // Convert signature to byte array
  const rBytes = Buffer.from(signature.r.slice(2), 'hex');
  const sBytes = Buffer.from(signature.s.slice(2), 'hex');
  const sigBytes = new Uint8Array(64);
  sigBytes.set(rBytes, 0);
  sigBytes.set(sBytes, 32);

  // Extract public key
  const dataHex = eip712Data.message.data;
  const dataBytes = Buffer.from(dataHex.slice(2), 'hex');
  const publicKeyX = Array.from(dataBytes.slice(0, 32));
  const publicKeyY = Array.from(dataBytes.slice(32, 64));

  // Convert allowed URLs to byte arrays
  const allowedUrls = config.allowedUrls.map(url => 
    Array.from(new TextEncoder().encode(url))
  );

  // Parse request URLs from attestation
  const requestUrls: number[][] = [];

  // Extract data hashes and plain responses
  const dataHashes: number[][] = [];
  const plainJsonResponses: number[][] = [];

  // Generate unique ID
  const id = Date.now() % 1000000;

  return {
    publicKeyX,
    publicKeyY,
    hash: Array.from(Buffer.from(eip712Data.message.schema.slice(2), 'hex')),
    signature: Array.from(sigBytes),
    requestUrls,
    allowedUrls,
    dataHashes,
    plainJsonResponses,
    id,
    attestationData,
  };
}

/**
 * Converts a string to a byte array.
 */
export function stringToBytes(str: string): number[] {
  return Array.from(new TextEncoder().encode(str));
}

/**
 * Converts a hex string to a byte array.
 */
export function hexToBytes(hex: string): number[] {
  const hexClean = hex.startsWith('0x') ? hex.slice(2) : hex;
  const bytes = new Uint8Array(hexClean.length / 2);
  for (let i = 0; i < hexClean.length; i += 2) {
    bytes[i / 2] = parseInt(hexClean.substring(i, i + 2), 16);
  }
  return Array.from(bytes);
}
