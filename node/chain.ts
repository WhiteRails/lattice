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

// ── Bytes32 helpers (labels → Solidity bytes32 via keccak256, or raw hex) ─────

/** `0x` + 64 hex, or any string → `ethers.id(string)`. */
export function labelToBytes32(label: string): string {
  const t = label.trim();
  if (/^0x[0-9a-fA-F]{64}$/.test(t)) return ethers.hexlify(t);
  return ethers.id(t);
}

export function readPublicKeyHashFromFile(filePath: string): string {
  const raw = fs.readFileSync(filePath, 'utf-8').trim();
  return ethers.keccak256(ethers.toUtf8Bytes(raw));
}

/**
 * Read operator private key from CLI: prefer --key-file (path outside the repo) over raw --key.
 */
export function resolvePrivateKeyFromCli(opts: { key?: string; keyFile?: string }): string {
  const k = opts.key?.trim();
  const f = opts.keyFile?.trim();
  if (k && f) throw new Error('Use only one of --key or --key-file');
  if (f) {
    const abs = path.isAbsolute(f) ? f : path.resolve(process.cwd(), f);
    if (!fs.existsSync(abs)) throw new Error(`Key file not found: ${abs}`);
    const raw = fs.readFileSync(abs, 'utf-8').trim();
    if (!raw) throw new Error('Key file is empty');
    return raw;
  }
  if (!k) throw new Error('Provide --key (hex) or --key-file (path outside the repo)');
  return k;
}

/** ASCII `label.lattice` (single label). Mirrors LatticeChain namespace rules. */
export function assertValidPublicLatticeFqdn(fqdn: string): void {
  const s = fqdn.trim();
  if (!/^[a-z0-9-]+\.lattice$/.test(s)) {
    throw new Error(
      'FQDN must be ASCII lowercase: one label [a-z0-9-]+ followed by `.lattice` (e.g. echo.lattice). Reserved slugs require the contract owner.',
    );
  }
}

function getSignerContract(rpcUrl: string, privateKey: string, contractAddress: string) {
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const wallet = new ethers.Wallet(privateKey, provider);
  const { abi } = getContractArtifacts();
  return new ethers.Contract(contractAddress, abi, wallet);
}

function getReadContract(rpcUrl: string, contractAddress: string) {
  const provider = new ethers.JsonRpcProvider(rpcUrl);
  const { abi } = getContractArtifacts();
  return new ethers.Contract(contractAddress, abi, provider);
}

function parseBytes32HexOrZero(v: string | undefined): string {
  if (v === undefined || v === '') return ethers.ZeroHash;
  const t = v.trim();
  if (!/^0x[0-9a-fA-F]{64}$/i.test(t)) {
    throw new Error(`Invalid bytes32 (expected 0x + 64 hex): ${v}`);
  }
  return ethers.hexlify(t);
}

function optionalBytes32(v: string | undefined): string {
  if (v === undefined || v === null) return ethers.ZeroHash;
  const t = String(v).trim();
  if (t === '' || t === '0') return ethers.ZeroHash;
  return parseBytes32HexOrZero(t);
}

// ── IssuerRegistry + CertType (onlyOwner) ───────────────────────────────────

export async function chainRegisterCertType(
  rpcUrl: string,
  privateKey: string,
  contractAddress: string,
  name: string,
  assuranceLevel: number,
): Promise<{ txHash: string; certTypeId: string }> {
  const certTypeId = labelToBytes32(name);
  const c = getSignerContract(rpcUrl, privateKey, contractAddress);
  const tx = await c.registerCertType(certTypeId, name.trim(), assuranceLevel);
  const receipt = await tx.wait();
  return { txHash: receipt.hash, certTypeId };
}

export async function chainRegisterIssuer(
  rpcUrl: string,
  privateKey: string,
  contractAddress: string,
  issuerLabel: string,
  typeLabel: string,
  publicKeyHash: string,
): Promise<{ txHash: string; issuerId: string }> {
  const issuerId = labelToBytes32(issuerLabel);
  const issuerType = labelToBytes32(typeLabel);
  const c = getSignerContract(rpcUrl, privateKey, contractAddress);
  const tx = await c.registerIssuer(issuerId, issuerType, publicKeyHash);
  const receipt = await tx.wait();
  return { txHash: receipt.hash, issuerId };
}

export async function chainSetIssuerPermission(
  rpcUrl: string,
  privateKey: string,
  contractAddress: string,
  issuerLabel: string,
  certTypeName: string,
  allowed: boolean,
): Promise<string> {
  const issuerId = labelToBytes32(issuerLabel);
  const certTypeId = labelToBytes32(certTypeName);
  const c = getSignerContract(rpcUrl, privateKey, contractAddress);
  const tx = await c.setIssuerPermission(issuerId, certTypeId, allowed);
  const receipt = await tx.wait();
  return receipt.hash;
}

// ── NamespaceRegistry ───────────────────────────────────────────────────────

export async function chainRegisterNamespace(
  rpcUrl: string,
  privateKey: string,
  contractAddress: string,
  fqdn: string,
  ownerIssuerLabel: string,
  serviceCertHash: string | undefined,
  metadataHash: string | undefined,
  namespaceAdmin: string | undefined,
  publicAccess: boolean,
  credentialMask: number,
  minAssuranceLevel: number,
): Promise<{ txHash: string; nameHash: string; ownerIssuerId: string }> {
  assertValidPublicLatticeFqdn(fqdn);
  const nameHash = ethers.id(fqdn.trim());
  const ownerIssuerId = labelToBytes32(ownerIssuerLabel.trim());
  const svc = optionalBytes32(serviceCertHash);
  const meta = optionalBytes32(metadataHash);
  const admin =
    namespaceAdmin !== undefined && namespaceAdmin.trim() !== ''
      ? ethers.getAddress(namespaceAdmin.trim())
      : ethers.ZeroAddress;
  const c = getSignerContract(rpcUrl, privateKey, contractAddress);
  const tx = await c.registerNamespace(
    fqdn.trim(),
    ownerIssuerId,
    svc,
    meta,
    admin,
    publicAccess,
    credentialMask,
    minAssuranceLevel,
  );
  const receipt = await tx.wait();
  return { txHash: receipt.hash, nameHash, ownerIssuerId };
}

export async function chainUpdateNamespaceServiceBinding(
  rpcUrl: string,
  privateKey: string,
  contractAddress: string,
  fqdn: string,
  serviceCertHash: string | undefined,
  metadataHash: string | undefined,
): Promise<string> {
  assertValidPublicLatticeFqdn(fqdn);
  const nameHash = ethers.id(fqdn.trim());
  const readC = getReadContract(rpcUrl, contractAddress);
  const row = await readC.namespaces(nameHash);
  if (row.ownerIssuerId === ethers.ZeroHash) {
    throw new Error('Unknown namespace');
  }
  const hasSvcArg = serviceCertHash !== undefined;
  const hasMetaArg = metadataHash !== undefined;
  if (!hasSvcArg && !hasMetaArg) {
    throw new Error('Provide at least one of serviceCertHash or metadataHash to update');
  }
  const svc = hasSvcArg ? optionalBytes32(serviceCertHash) : row.serviceCertHash;
  const meta = hasMetaArg ? optionalBytes32(metadataHash) : row.metadataHash;
  const c = getSignerContract(rpcUrl, privateKey, contractAddress);
  const tx = await c.updateNamespaceServiceBinding(fqdn.trim(), svc, meta);
  const receipt = await tx.wait();
  return receipt.hash;
}

export async function chainSetNamespaceAccessPolicy(
  rpcUrl: string,
  privateKey: string,
  contractAddress: string,
  fqdn: string,
  publicAccess: boolean,
  credentialMask: number,
  minAssuranceLevel: number,
): Promise<string> {
  assertValidPublicLatticeFqdn(fqdn);
  const c = getSignerContract(rpcUrl, privateKey, contractAddress);
  const tx = await c.setNamespaceAccessPolicy(fqdn.trim(), publicAccess, credentialMask, minAssuranceLevel);
  const receipt = await tx.wait();
  return receipt.hash;
}

export async function chainGetNamespace(
  rpcUrl: string,
  contractAddress: string,
  fqdn: string,
): Promise<{
  nameHash: string;
  ownerIssuerId: string;
  serviceCertHash: string;
  metadataHash: string;
  active: boolean;
  namespaceAdmin: string;
  publicAccess: boolean;
  credentialMask: number;
  minAssuranceLevel: number;
}> {
  const nameHash = ethers.id(fqdn.trim());
  const c = getReadContract(rpcUrl, contractAddress);
  const row = await c.namespaces(nameHash);
  return {
    nameHash,
    ownerIssuerId: row.ownerIssuerId,
    serviceCertHash: row.serviceCertHash,
    metadataHash: row.metadataHash,
    active: row.active,
    namespaceAdmin: row.namespaceAdmin,
    publicAccess: row.publicAccess,
    credentialMask: Number(row.credentialMask),
    minAssuranceLevel: Number(row.minAssuranceLevel),
  };
}

export async function chainGetIssuer(
  rpcUrl: string,
  contractAddress: string,
  issuerLabel: string,
): Promise<{ issuerId: string; issuerType: string; publicKeyHash: string; active: boolean }> {
  const issuerId = labelToBytes32(issuerLabel.trim());
  const c = getReadContract(rpcUrl, contractAddress);
  const row = await c.issuers(issuerId);
  return {
    issuerId,
    issuerType: row.issuerType,
    publicKeyHash: row.publicKeyHash,
    active: row.active,
  };
}

export async function chainGetCertType(
  rpcUrl: string,
  contractAddress: string,
  name: string,
): Promise<{ certTypeId: string; name: string; assuranceLevel: number; active: boolean }> {
  const certTypeId = labelToBytes32(name.trim());
  const c = getReadContract(rpcUrl, contractAddress);
  const row = await c.certTypes(certTypeId);
  return {
    certTypeId,
    name: row.name,
    assuranceLevel: Number(row.assuranceLevel),
    active: row.active,
  };
}

export async function chainIssuerCanIssue(
  rpcUrl: string,
  contractAddress: string,
  issuerLabel: string,
  certTypeName: string,
): Promise<boolean> {
  const issuerId = labelToBytes32(issuerLabel.trim());
  const certTypeId = labelToBytes32(certTypeName.trim());
  const c = getReadContract(rpcUrl, contractAddress);
  return c.canIssue(issuerId, certTypeId);
}

/** keccak256(UTF-8 bytes) of the slug string (no dots), matching `reservedOfficialLatticeSlugs` keys. */
export function reservedLatticeSlugHash(slug: string): string {
  return ethers.keccak256(ethers.toUtf8Bytes(slug.trim()));
}

export async function chainGetReservedOfficialSlug(
  rpcUrl: string,
  contractAddress: string,
  slug: string,
): Promise<boolean> {
  const h = reservedLatticeSlugHash(slug);
  const c = getReadContract(rpcUrl, contractAddress);
  return c.reservedOfficialLatticeSlugs(h);
}

export async function chainTransferOwnership(
  rpcUrl: string,
  privateKey: string,
  contractAddress: string,
  newOwnerAddress: string,
): Promise<string> {
  const c = getSignerContract(rpcUrl, privateKey, contractAddress);
  const tx = await c.transferOwnership(newOwnerAddress);
  const receipt = await tx.wait();
  return receipt.hash;
}

export async function chainSetReservedOfficialSlug(
  rpcUrl: string,
  privateKey: string,
  contractAddress: string,
  slug: string,
  reserved: boolean,
): Promise<string> {
  const c = getSignerContract(rpcUrl, privateKey, contractAddress);
  const tx = await c.setReservedOfficialSlug(slug.trim(), reserved);
  const receipt = await tx.wait();
  return receipt.hash;
}
