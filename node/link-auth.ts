import * as crypto from 'crypto';
import { z } from 'zod';
import type { LatticeNodeRole } from './node-config';
import type { NodeCryptoBackend, NodeKeyDescriptor } from './node-crypto';
import { stableStringify } from './message';

const LABEL_RE = /^[a-z0-9._-]{1,64}$/;
const NONCE_RE = /^[A-Za-z0-9_-]{32}$/;
const KEY_ID_RE = /^[a-f0-9]{64}$/;
const MAX_LINK_AUTH_AGE_MS = 30_000;

const LinkChallengeSchema = z.object({
  version: z.literal(1),
  type: z.literal('link_auth_challenge'),
  server_label: z.string().regex(LABEL_RE),
  identity_key_id: z.string().regex(KEY_ID_RE),
  nonce: z.string().regex(NONCE_RE),
  timestamp: z.string().datetime({ offset: true }),
  signature: z.string().regex(/^[A-Za-z0-9_-]{86}$/),
}).strict();

const LinkProofSchema = z.object({
  version: z.literal(1),
  type: z.literal('link_auth_proof'),
  client_label: z.string().regex(LABEL_RE),
  client_role: z.enum(['entry', 'relay', 'gateway']),
  server_label: z.string().regex(LABEL_RE),
  identity_key_id: z.string().regex(KEY_ID_RE),
  nonce: z.string().regex(NONCE_RE),
  timestamp: z.string().datetime({ offset: true }),
  signature: z.string().regex(/^[A-Za-z0-9_-]{86}$/),
}).strict();

export type LinkAuthChallenge = z.infer<typeof LinkChallengeSchema>;
export type LinkAuthProof = z.infer<typeof LinkProofSchema>;

export async function createLinkAuthChallenge(
  serverLabel: string,
  identityKey: NodeKeyDescriptor,
  backend: NodeCryptoBackend,
  now = Date.now(),
): Promise<LinkAuthChallenge> {
  if (!LABEL_RE.test(serverLabel) || identityKey.purpose !== 'identity' || identityKey.algorithm !== 'ed25519') {
    throw new Error('Invalid server link-auth identity');
  }
  const unsigned = {
    version: 1 as const,
    type: 'link_auth_challenge' as const,
    server_label: serverLabel,
    identity_key_id: identityKey.keyId,
    nonce: crypto.randomBytes(24).toString('base64url'),
    timestamp: new Date(now).toISOString(),
  };
  const signature = await backend.signEd25519(identityKey.keyId, authPayload(unsigned));
  return LinkChallengeSchema.parse({ ...unsigned, signature: signature.toString('base64url') });
}

export function verifyLinkAuthChallenge(
  input: unknown,
  expectedServerLabel: string,
  expectedIdentity: NodeKeyDescriptor,
  now = Date.now(),
): LinkAuthChallenge {
  const challenge = LinkChallengeSchema.parse(input);
  if (challenge.server_label !== expectedServerLabel || challenge.identity_key_id !== expectedIdentity.keyId) {
    throw new Error('Link-auth server identity mismatch');
  }
  assertFresh(challenge.timestamp, now);
  if (!verifyIdentitySignature(expectedIdentity.publicKey, authPayload(unsignedChallenge(challenge)), challenge.signature)) {
    throw new Error('Invalid link-auth server signature');
  }
  return challenge;
}

export async function createLinkAuthProof(
  challenge: LinkAuthChallenge,
  clientLabel: string,
  clientRole: LatticeNodeRole,
  identityKey: NodeKeyDescriptor,
  backend: NodeCryptoBackend,
  now = Date.now(),
): Promise<LinkAuthProof> {
  if (!LABEL_RE.test(clientLabel) || identityKey.purpose !== 'identity' || identityKey.algorithm !== 'ed25519') {
    throw new Error('Invalid client link-auth identity');
  }
  const unsigned = {
    version: 1 as const,
    type: 'link_auth_proof' as const,
    client_label: clientLabel,
    client_role: clientRole,
    server_label: challenge.server_label,
    identity_key_id: identityKey.keyId,
    nonce: challenge.nonce,
    timestamp: new Date(now).toISOString(),
  };
  const signature = await backend.signEd25519(identityKey.keyId, authPayload(unsigned));
  return LinkProofSchema.parse({ ...unsigned, signature: signature.toString('base64url') });
}

export function verifyLinkAuthProof(
  input: unknown,
  challenge: LinkAuthChallenge,
  expectedClientLabel: string,
  expectedClientRole: LatticeNodeRole,
  expectedIdentity: NodeKeyDescriptor,
  now = Date.now(),
): LinkAuthProof {
  const proof = LinkProofSchema.parse(input);
  if (proof.client_label !== expectedClientLabel || proof.client_role !== expectedClientRole ||
      proof.server_label !== challenge.server_label || proof.nonce !== challenge.nonce ||
      proof.identity_key_id !== expectedIdentity.keyId) {
    throw new Error('Link-auth client identity mismatch');
  }
  assertFresh(proof.timestamp, now);
  if (!verifyIdentitySignature(expectedIdentity.publicKey, authPayload(unsignedProof(proof)), proof.signature)) {
    throw new Error('Invalid link-auth client signature');
  }
  return proof;
}

function verifyIdentitySignature(publicKeyB64: string, payload: Buffer, signatureB64Url: string): boolean {
  try {
    const key = crypto.createPublicKey({ key: Buffer.from(publicKeyB64, 'base64'), format: 'der', type: 'spki' });
    if (key.asymmetricKeyType !== 'ed25519') return false;
    return crypto.verify(null, payload, key, Buffer.from(signatureB64Url, 'base64url'));
  } catch {
    return false;
  }
}

function authPayload(value: object): Buffer {
  return Buffer.from(`lattice-link-auth-v1\0${stableStringify(value)}`, 'utf8');
}

function assertFresh(timestamp: string, now: number): void {
  const parsed = new Date(timestamp).getTime();
  if (!Number.isFinite(parsed) || Math.abs(now - parsed) > MAX_LINK_AUTH_AGE_MS) throw new Error('Stale link-auth message');
}

function unsignedChallenge(value: LinkAuthChallenge) {
  const { signature: _signature, ...unsigned } = value;
  return unsigned;
}

function unsignedProof(value: LinkAuthProof) {
  const { signature: _signature, ...unsigned } = value;
  return unsigned;
}
