import * as crypto from 'crypto';
import { AgentCert, AgentCertSchema } from './types';

export interface KeyPair {
  publicKey: string;
  privateKey: string;
}

/**
 * Generates an Ed25519 key pair for cryptographic operations.
 */
export function generateKeyPair(): KeyPair {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return { publicKey, privateKey };
}

/**
 * Creates an Agent Certificate structure.
 */
export function createAgentCert(params: {
  agent_id: string;
  owner_org: string;
  agent_type: string;
  version: string;
  public_key: string;
  issuer: string;
  allowed_capability_classes: string[];
  forbidden_capability_classes: string[];
  expires_in_days?: number;
}): AgentCert {
  const now = new Date();
  const issued_at = now.toISOString();

  let expires_at: string | undefined;
  if (params.expires_in_days) {
    const expiry = new Date(now);
    expiry.setDate(expiry.getDate() + params.expires_in_days);
    expires_at = expiry.toISOString();
  }

  const cert: AgentCert = {
    id: `cert:${crypto.randomBytes(8).toString('hex')}`,
    type: 'AgentCert',
    agent_id: params.agent_id,
    owner_org: params.owner_org,
    agent_type: params.agent_type,
    version: params.version,
    public_key: params.public_key,
    issuer: params.issuer,
    issued_at,
    expires_at,
    allowed_capability_classes: params.allowed_capability_classes,
    forbidden_capability_classes: params.forbidden_capability_classes,
  };

  return AgentCertSchema.parse(cert);
}

/**
 * Signs data using a private key.
 */
export function signData(data: string | Buffer, privateKey: string): string {
  // For Ed25519 in Node.js, the algorithm should be null
  const signature = crypto.sign(null, Buffer.from(data), privateKey);
  return signature.toString('base64');
}

/**
 * Verifies a signature using a public key.
 */
export function verifySignature(data: string | Buffer, signature: string, publicKey: string): boolean {
  return crypto.verify(null, Buffer.from(data), publicKey, Buffer.from(signature, 'base64'));
}

/**
 * Verifies if an Agent Certificate is currently valid.
 */
export function isCertValid(cert: AgentCert): boolean {
  const now = new Date();
  const issuedAt = new Date(cert.issued_at);
  if (issuedAt > now) return false;
  if (cert.expires_at) {
    const expiresAt = new Date(cert.expires_at);
    if (expiresAt < now) return false;
  }
  return true;
}
