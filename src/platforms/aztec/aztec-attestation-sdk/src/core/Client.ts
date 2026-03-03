/**
 * Aztec Client for Primus Attestation SDK
 * 
 * Handles connection to Aztec network (local or devnet),
 * account management, and utility functions.
 */

import { AccountWallet, createWallet } from "@aztec/aztec.js";
import type { AztecNode } from "@aztec/aztec.js/node";
import { createPXEClient } from "@aztec/aztec.js/pxe";

/**
 * Client mode: 'local' for sandbox, 'devnet' for public testnet
 */
export type ClientMode = 'local' | 'devnet';

/**
 * Client configuration
 */
export interface ClientConfig {
  /** Node URL */
  nodeUrl: string;
  /** Client mode */
  mode: ClientMode;
}

/**
 * Payment method for transaction fees
 */
export interface PaymentMethod {
  // Payment method details (implementation-specific)
  type: string;
  amount: bigint;
}

/**
 * Aztec client for attestation operations
 */
export class Client {
  private nodeUrl: string;
  private mode: ClientMode;
  private pxeClient: any;
  private wallet: AccountWallet | null = null;

  constructor(config: ClientConfig) {
    this.nodeUrl = config.nodeUrl;
    this.mode = config.mode;
  }

  /**
   * Initialize the client and connect to the network.
   * For devnet, this may take 2-5 minutes.
   * For local sandbox, this is instant.
   */
  async initialize(): Promise<void> {
    // Create PXE client
    this.pxeClient = createPXEClient(this.nodeUrl);
    
    // Create wallet for the first account
    if (this.mode === 'local') {
      // Local sandbox: get account 0 instantly
      this.wallet = await createWallet(this.pxeClient, 0);
    } else {
      // Devnet: deploy account (takes 2-5 minutes)
      this.wallet = await createWallet(this.pxeClient);
    }
  }

  /**
   * Get the wallet instance.
   * Must call initialize() first.
   */
  getWallet(): AccountWallet {
    if (!this.wallet) {
      throw new Error("Client not initialized. Call initialize() first.");
    }
    return this.wallet;
  }

  /**
   * Get account by index.
   * For local mode, accounts are instant.
   * For devnet, accounts must be deployed first.
   */
  async getAccount(index: number = 0): Promise<AccountWallet> {
    if (this.mode === 'local') {
      return await createWallet(this.pxeClient, index);
    } else {
      // For devnet, return the deployed wallet
      if (!this.wallet) {
        await this.initialize();
      }
      return this.wallet!;
    }
  }

  /**
   * Get the Aztec node instance.
   */
  getNode(): AztecNode {
    return this.pxeClient;
  }

  /**
   * Check if client is in devnet mode.
   */
  isDevnet(): boolean {
    return this.mode === 'devnet';
  }

  /**
   * Get payment method for transaction fees.
   * Only needed for devnet mode.
   */
  getPaymentMethod(): PaymentMethod | null {
    if (this.mode === 'devnet') {
      // Return devnet payment method
      return {
        type: 'devnet',
        amount: 1000000n,  // Example fee
      };
    }
    return null;
  }

  /**
   * Hash a list of URLs using Poseidon2.
   * Used for storing allowed URLs in contract storage.
   * 
   * @param urls - List of URLs to hash
   * @returns Array of 3 Poseidon2 hashes (padded with zeros if needed)
   */
  async hashUrls(urls: string[]): Promise<[bigint, bigint, bigint]> {
    const { poseidon2Hash } = await import("@aztec/foundation/crypto");
    
    const hashes: bigint[] = [];
    for (const url of urls.slice(0, 3)) {
      const bytes = new TextEncoder().encode(url);
      const fields = Array.from(bytes).map(b => BigInt(b));
      
      // Pad to 1024 fields
      while (fields.length < 1024) {
        fields.push(0n);
      }
      
      const hash = await poseidon2Hash(fields);
      hashes.push(hash);
    }
    
    // Pad with zeros if less than 3 URLs
    while (hashes.length < 3) {
      hashes.push(0n);
    }
    
    return [hashes[0], hashes[1], hashes[2]];
  }

  /**
   * Clean up client resources.
   * Should be called when done with the client.
   */
  async cleanup(): Promise<void> {
    if (this.pxeClient) {
      // Close PXE connection
      await this.pxeClient.stop?.();
    }
    this.wallet = null;
  }
}

/**
 * Create a new client instance.
 * 
 * @example
 * ```typescript
 * // Devnet
 * const client = new Client({
 *   nodeUrl: "https://next.devnet.aztec-labs.com",
 *   mode: "devnet"
 * });
 * await client.initialize();
 * 
 * // Local sandbox
 * const client = new Client({
 *   nodeUrl: "http://localhost:8080",
 *   mode: "local"
 * });
 * await client.initialize();
 * ```
 */
export function createClient(config: ClientConfig): Client {
  return new Client(config);
}
