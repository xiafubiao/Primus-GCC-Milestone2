/**
 * Contract helpers for Primus attestation verifier contracts
 */

import type { AztecAddress } from "@aztec/aztec.js/addresses";
import type { AztecNode } from "@aztec/aztec.js/node";
import { getDecodedPublicEvents } from "@aztec/aztec.js/events";
import type { Client } from "../core/Client.js";

/**
 * Grumpkin curve point for Pedersen commitments
 */
export interface EmbeddedCurvePoint {
  x: bigint;
  y: bigint;
  is_infinite: boolean;
}

/**
 * Deployment parameters for attestation verifier contracts
 */
export interface ContractDeploymentParams {
  /** Admin address that can update allowed URLs */
  admin: AztecAddress;
  /** List of allowed URLs (will be hashed before storage) */
  allowedUrls: string[];
  /** Point H for commitment verification (optional, hash-based only if omitted) */
  pointH?: EmbeddedCurvePoint;
  /** Sender address for deployment */
  from: AztecAddress;
  /** Deployment timeout in milliseconds */
  timeout?: number;
}

/**
 * Event emitted upon successful attestation verification
 */
export interface SuccessEvent {
  /** Address that initiated the verification */
  sender: AztecAddress;
  /** Contract address */
  contract_address: AztecAddress;
  /** Unique attestation ID */
  id: bigint;
}

/**
 * Helper utilities for attestation verifier contracts
 */
export class ContractHelpers {
  /**
   * Deploys an attestation verifier contract with hashed URLs.
   * Automatically handles fee payment for devnet mode.
   * 
   * @param contractClass - Contract class from generated bindings
   * @param client - Aztec client instance
   * @param params - Deployment parameters
   * @returns Deployed contract instance
   * 
   * @example
   * ```typescript
   * const contract = await ContractHelpers.deployContract(
   *   BusinessProgramContract,
   *   client,
   *   {
   *     admin: alice.address,
   *     allowedUrls: ['https://api.example.com'],
   *     pointH: { x: 123n, y: 456n, is_infinite: false },
   *     from: alice.address,
   *     timeout: 1200000
   *   }
   * );
   * ```
   */
  static async deployContract<T>(
    contractClass: any,
    client: Client,
    params: ContractDeploymentParams
  ): Promise<T> {
    const wallet = client.getWallet();
    
    // Hash the allowed URLs using Poseidon2
    const hashedUrls = await client.hashUrls(params.allowedUrls);

    // Build deployment arguments
    const deploymentArgs = params.pointH
      ? [params.admin, hashedUrls, params.pointH]  // Commitment-based
      : [params.admin, hashedUrls];                 // Hash-based

    // Build send options
    const sendOptions: any = { from: params.from };

    // Add fee payment for devnet mode
    if (client.isDevnet()) {
      const paymentMethod = client.getPaymentMethod();
      if (paymentMethod) {
        sendOptions.fee = { paymentMethod };
      }
    }

    // Deploy contract
    const deployment = contractClass
      .deploy(wallet, ...deploymentArgs)
      .send(sendOptions);

    // Wait for deployment with optional timeout
    if (params.timeout) {
      return await deployment.deployed({ timeout: params.timeout });
    }

    return await deployment.deployed();
  }

  /**
   * Retrieves SuccessEvent instances from a specific block.
   * 
   * @param node - Aztec node instance
   * @param eventType - Event type class from bindings
   * @param blockNumber - Block number to search
   * @param maxLookback - Maximum blocks to look back (default: 2)
   * @returns Array of success events
   * 
   * @example
   * ```typescript
   * const events = await ContractHelpers.getSuccessEvents(
   *   client.getNode(),
   *   BusinessProgramContract.events.SuccessEvent,
   *   result.blockNumber!
   * );
   * console.log("Events emitted:", events.length > 0);
   * ```
   */
  static async getSuccessEvents(
    node: AztecNode,
    eventType: any,
    blockNumber: number,
    maxLookback: number = 2
  ): Promise<SuccessEvent[]> {
    try {
      return await getDecodedPublicEvents(node, eventType, blockNumber, maxLookback);
    } catch (error) {
      console.error("Error fetching success events:", error);
      return [];
    }
  }

  /**
   * Converts a URL string to a byte array.
   */
  static urlToBytes(url: string): number[] {
    return Array.from(new TextEncoder().encode(url));
  }

  /**
   * Converts a byte array to a URL string.
   */
  static bytesToUrl(bytes: number[]): string {
    return new TextDecoder().decode(new Uint8Array(bytes));
  }
}
