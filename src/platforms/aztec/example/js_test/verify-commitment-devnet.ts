/**
 * End-to-end example: Verify commitment-based Primus attestation on Aztec devnet
 * 
 * This script demonstrates the complete workflow:
 * 1. Initialize Aztec client
 * 2. Parse attestation data
 * 3. Deploy verifier contract
 * 4. Call verify_comm function
 * 5. Wait for success event
 * 
 * Prerequisites:
 * - Aztec Sandbox 3.0.0-devnet.6-patch.1
 * - Built att_verifier_parsing and aztec-attestation-sdk libraries
 * - Compiled BusinessProgram contract with bindings in ./bindings/
 */

import * as fs from 'fs';
import { Client, ContractHelpers, parseCommitmentAttestation } from 'aztec-attestation-sdk';
import { BusinessProgramContract } from './bindings/BusinessProgram.js';

// Configuration
const ATT_PATH = './fixtures/attestation.json';
const ALLOWED_URLS = [
  'https://api.binance.com/api/v3/account',
  'https://api.example.com/data',
  'https://api.example.com/info',
];
const MAX_RESPONSE_NUM = 10;
const GRUMPKIN_BATCH_SIZE = 65;

// Unique point H for this business case
// This should be generated once and reused for all deployments
const POINT_H = {
  x: 19978178333943292355349418156359056918133515370613875064303296301489725624535n,
  y: 13201885744872984780649110422697192888453633882501354541258277493771319153464n,
  is_infinite: false,
};

async function main() {
  console.log('🚀 Starting commitment-based attestation verification on devnet...\n');

  // Step 1: Initialize client
  console.log('📡 Initializing Aztec client...');
  const client = new Client({
    nodeUrl: 'https://next.devnet.aztec-labs.com',
    mode: 'devnet',
  });

  await client.initialize();
  console.log('✅ Client initialized\n');

  // Step 2: Get account
  console.log('👤 Getting account...');
  const alice = await client.getAccount();
  console.log(`   Address: ${alice.address}\n`);

  // Step 3: Load and parse attestation
  console.log('📄 Loading attestation data...');
  const attestationData = JSON.parse(fs.readFileSync(ATT_PATH, 'utf-8'));
  
  const parsed = parseCommitmentAttestation(attestationData, {
    maxResponseNum: MAX_RESPONSE_NUM,
    allowedUrls: ALLOWED_URLS,
    grumpkinBatchSize: GRUMPKIN_BATCH_SIZE,
  });
  console.log('✅ Attestation parsed\n');

  // Step 4: Deploy contract
  console.log('📦 Deploying BusinessProgram contract...');
  console.log('   This may take 2-5 minutes on devnet...\n');
  
  const contract = await ContractHelpers.deployContract<BusinessProgramContract>(
    BusinessProgramContract,
    client,
    {
      admin: alice.address,
      allowedUrls: ALLOWED_URLS,
      pointH: POINT_H,
      from: alice.address,
      timeout: 1200000,  // 20 minutes timeout
    }
  );

  const contractAddress = await contract.getAddress();
  console.log(`✅ Contract deployed: ${contractAddress}\n`);

  // Step 5: Verify attestation
  console.log('🔐 Verifying attestation...');
  const paymentMethod = client.getPaymentMethod();
  
  const result = await contract.methods
    .verify_comm(
      parsed.publicKeyX,
      parsed.publicKeyY,
      parsed.hash,
      parsed.signature,
      parsed.requestUrls,
      parsed.allowedUrls,
      parsed.commitments,
      parsed.randomScalars,
      parsed.msgsChunks,
      parsed.msgs,
      POINT_H,
      BigInt(parsed.id)
    )
    .send({ 
      from: alice.address, 
      fee: { paymentMethod } 
    })
    .wait({ timeout: 180000 });  // 3 minutes timeout

  console.log(`   Transaction status: ${result.status}`);
  console.log(`   Block number: ${result.blockNumber}\n`);

  // Step 6: Check for success event
  console.log('🔍 Checking for success event...');
  if (result.status === 'success') {
    const events = await ContractHelpers.getSuccessEvents(
      client.getNode(),
      BusinessProgramContract.events.SuccessEvent,
      result.blockNumber!
    );
    
    if (events.length > 0) {
      console.log('✅ Success event emitted!');
      console.log(`   Events found: ${events.length}`);
      console.log(`   Sender: ${events[0].sender}`);
      console.log(`   Contract: ${events[0].contract_address}`);
      console.log(`   ID: ${events[0].id}\n`);
    } else {
      console.log('⚠️  No events found (yet). Public function may still be pending.\n');
    }
  } else {
    console.log('❌ Transaction failed!\n');
  }

  // Cleanup
  console.log('🧹 Cleaning up...');
  await client.cleanup();
  console.log('✅ Done!\n');
}

// Run the example
main().catch((error) => {
  console.error('❌ Error:', error);
  process.exit(1);
});
