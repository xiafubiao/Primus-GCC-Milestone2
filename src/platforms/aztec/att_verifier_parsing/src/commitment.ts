/**
 * Pedersen commitment utilities for Primus attestation parsing
 * Implements the same logic as the Rust reference implementation
 */

import type { Point } from "./types.js";

/**
 * Converts a 32-byte array to a scalar (bigint).
 * Matches the Rust bytes2scalar implementation.
 * 
 * Algorithm:
 * 1. Split 32 bytes into 4 limbs of 8 bytes each
 * 2. Convert each limb to bigint (big-endian)
 * 3. Combine limbs with 64-bit shifts
 * 
 * @param bytes - 32-byte array to convert
 * @returns Scalar as bigint
 */
export function bytes32ToBigInt(bytes: Uint8Array): bigint {
  if (bytes.length !== 32) {
    throw new Error(`Expected 32 bytes, got ${bytes.length}`);
  }

  const limbs: bigint[] = [];

  // Process 4 limbs of 8 bytes each
  for (let i = 3; i >= 0; i--) {
    const start = i * 8;
    const chunk = bytes.slice(start, start + 8);
    let limb = 0n;
    for (let j = 0; j < 8; j++) {
      limb = (limb << 8n) | BigInt(chunk[j]);
    }
    limbs.push(limb);
  }

  // Combine limbs with 64-bit shifts
  let result = 0n;
  for (let i = 0; i < 4; i++) {
    result = result | (limbs[i] << BigInt(i * 64));
  }

  return result;
}

/**
 * Generates the basis of 2^i powers as bigints for batch operations.
 * Used for bit packing in commitment generation.
 * 
 * @param batchSize - Number of elements in the batch
 * @returns Array of 2^i powers as bigints
 */
export function generateExp(batchSize: number): bigint[] {
  const vec: bigint[] = [];
  
  for (let i = 0; i < batchSize; i++) {
    const j = Math.floor(i / 8);
    const k = i % 8;
    const bytes = new Uint8Array(32);
    bytes[31 - j] |= 1 << k;

    const scalar = bytes32ToBigInt(bytes);
    vec.push(scalar);
  }
  
  return vec;
}

/**
 * Splits a JSON response string into field element chunks using bit packing.
 * Matches the Rust split_json_response function.
 * 
 * Algorithm:
 * 1. Encode JSON string to UTF-8 bytes
 * 2. Reverse byte order
 * 3. Convert to bit array
 * 4. Pack bits into field elements using powers of 2
 * 
 * @param jsonResponse - JSON response string to split
 * @param batchSize - Number of bits per field element (typically 65 for Grumpkin)
 * @returns Array of field elements as bigints
 */
export function computeMsgsChunks(jsonResponse: string, batchSize: number): bigint[] {
  // Encode to UTF-8 bytes and reverse
  let bytes = Array.from(new TextEncoder().encode(jsonResponse));
  bytes.reverse();

  // Convert to bit array
  const bits: boolean[] = [];
  for (const byte of bytes) {
    for (let i = 0; i < 8; i++) {
      const b = (byte >> i) & 1;
      bits.push(b !== 0);
    }
  }

  // Generate powers of 2 for bit packing
  const exp = generateExp(batchSize);

  // Pack bits into field elements
  const vec: bigint[] = [];
  const chunkLen = Math.ceil(bits.length / batchSize);
  let index = 0;

  for (let _ = 0; _ < chunkLen; _++) {
    let scalar = 0n;
    for (let j = 0; j < batchSize; j++) {
      if (index >= bits.length) break;
      if (bits[index]) {
        scalar = scalar + exp[j];
      }
      index++;
    }
    vec.push(scalar);
  }

  return vec;
}

/**
 * Parses commitment points from hex-encoded verification array.
 * Each point is expected to be an uncompressed EC point (04 | x | y).
 * 
 * Format: 0x04 || x (32 bytes) || y (32 bytes) = 65 bytes total
 * 
 * @param verificationArray - Array of hex-encoded points
 * @returns Array of Point objects with x, y coordinates as bigints
 */
export function parseCommitments(verificationArray: string[]): Point[] {
  return verificationArray.map((hex: string) => {
    // Remove 0x prefix if present
    const hexClean = hex.startsWith('0x') ? hex.slice(2) : hex;
    const bytes = Buffer.from(hexClean, "hex");

    // Validate uncompressed point format
    if (bytes.length !== 65 || bytes[0] !== 0x04) {
      throw new Error("Expected uncompressed EC point (04 | x | y), got " + bytes.length + " bytes");
    }

    const xBytes = new Uint8Array(bytes.slice(1, 33));
    const yBytes = new Uint8Array(bytes.slice(33, 65));

    return {
      x: bytesToBigInt(xBytes),
      y: bytesToBigInt(yBytes),
      is_infinite: false,
    };
  });
}

/**
 * Parses random scalars from hex-encoded array.
 * 
 * @param randomHexArray - Array of hex-encoded scalars
 * @returns Array of bigints
 */
export function parseRandomScalars(randomHexArray: string[]): bigint[] {
  return randomHexArray.map((hex: string) => {
    const hexClean = hex.startsWith('0x') ? hex.slice(2) : hex;
    return BigInt("0x" + hexClean);
  });
}

/**
 * Converts a Uint8Array to a bigint (big-endian).
 * 
 * @param bytes - Byte array to convert
 * @returns Bigint representation
 */
export function bytesToBigInt(bytes: Uint8Array): bigint {
  let result = 0n;
  for (let i = 0; i < bytes.length; i++) {
    result = (result << 8n) | BigInt(bytes[i]);
  }
  return result;
}

/**
 * Converts a bigint to a byte array (big-endian).
 * 
 * @param value - Bigint to convert
 * @param length - Desired byte array length (pads with zeros if needed)
 * @returns Uint8Array
 */
export function bigIntToBytes(value: bigint, length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  let i = length - 1;
  while (value > 0n && i >= 0) {
    bytes[i] = Number(value & 0xffn);
    value = value >> 8n;
    i--;
  }
  return bytes;
}
