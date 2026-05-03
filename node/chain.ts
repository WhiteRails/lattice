import { ethers } from 'ethers';
import * as fs from 'fs';
import * as path from 'path';
import { BatchMetadata } from './batch';

function getContractArtifacts() {
  const dir = path.join(__dirname, '../contracts');
  const abiPath = path.join(dir, 'contracts_LatticeChain_sol_LatticeChain.abi');
  const binPath = path.join(dir, 'contracts_LatticeChain_sol_LatticeChain.bin');
  
  if (!fs.existsSync(abiPath) || !fs.existsSync(binPath)) {
    throw new Error("Contract artifacts not found. Run 'npm run build:contracts' or compile LatticeChain.sol");
  }
  
  return {
    abi: JSON.parse(fs.readFileSync(abiPath, 'utf-8')),
    bytecode: '0x' + fs.readFileSync(binPath, 'utf-8')
  };
}

export async function deployLatticeChain(rpcUrl: string, privateKey: string): Promise<string> {
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const wallet = new ethers.Wallet(privateKey, provider);
  const { abi, bytecode } = getContractArtifacts();

  const factory = new ethers.ContractFactory(abi, bytecode, wallet);
  const contract = await factory.deploy();
  await contract.waitForDeployment();
  return await contract.getAddress();
}

export async function submitCheckpoint(
  batch: BatchMetadata,
  rpcUrl: string,
  privateKey: string,
  contractAddress: string
): Promise<string> {
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const wallet = new ethers.Wallet(privateKey, provider);
  const { abi } = getContractArtifacts();

  const contract = new ethers.Contract(contractAddress, abi, wallet);

  // Convert batch_id to bytes32 (hash it to ensure exact 32 bytes)
  const batchIdBytes = ethers.id(batch.batch_id);
  
  const fromTs = Math.floor(new Date(batch.from_timestamp).getTime() / 1000) || 0;
  const toTs = Math.floor(new Date(batch.to_timestamp).getTime() / 1000) || 0;

  const tx = await contract.submitCheckpoint(
    batchIdBytes,
    batch.merkle_root,
    fromTs,
    toTs,
    batch.action_count
  );

  const receipt = await tx.wait();
  return receipt.hash;
}

export async function verifyCheckpointOnChain(
  batchId: string,
  rpcUrl: string,
  contractAddress: string
): Promise<{ anchored: boolean; merkleRoot?: string; signer?: string }> {
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const { abi } = getContractArtifacts();
  
  const contract = new ethers.Contract(contractAddress, abi, provider);
  const batchIdBytes = ethers.id(batchId);

  const checkpoint = await contract.checkpoints(batchIdBytes);
  
  // checkpoint returns an array/struct depending on ethers version, in ethers v6 we can access by property name
  if (checkpoint.merkleRoot === ethers.ZeroHash) {
    return { anchored: false };
  }

  return {
    anchored: true,
    merkleRoot: checkpoint.merkleRoot,
    signer: checkpoint.signer
  };
}
