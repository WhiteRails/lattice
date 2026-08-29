import * as crypto from 'crypto';
import { Aes256Gcm, CipherSuite, HkdfSha256 } from '@hpke/core';
import { DhkemX25519HkdfSha256 } from '@hpke/dhkem-x25519';
import { z } from 'zod';
import { stableStringify } from './message';

export const LATTICE_HPKE_SUITE = 'DHKEM-X25519-HKDF-SHA256/HKDF-SHA256/AES-256-GCM' as const;
export const LATTICE_HPKE_INFO = Buffer.from('lattice-service-e2e-v1', 'utf8');
export const MAX_HPKE_CIPHERTEXT_BYTES = 2 * 1024 * 1024;

const suite = new CipherSuite({
  kem: new DhkemX25519HkdfSha256(),
  kdf: new HkdfSha256(),
  aead: new Aes256Gcm(),
});

const B64URL_32_RE = /^[A-Za-z0-9_-]{43}$/;
const KEY_ID_RE = /^[a-f0-9]{64}$/;
const REQUEST_ID_RE = /^[a-f0-9]{32}$/;
const ROUTE_HASH_RE = /^(?:0x)?[a-f0-9]{64}$/;

export const HpkeEnvelopeSchema = z.object({
  version: z.literal(1),
  suite: z.literal(LATTICE_HPKE_SUITE),
  direction: z.enum(['request', 'response']),
  key_id: z.string().regex(KEY_ID_RE),
  request_id: z.string().regex(REQUEST_ID_RE),
  route_hash: z.string().regex(ROUTE_HASH_RE),
  created_at: z.string().datetime({ offset: true }),
  expires_at: z.string().datetime({ offset: true }),
  enc: z.string().regex(B64URL_32_RE),
  ciphertext: z.string().min(1),
}).strict().superRefine((value, ctx) => {
  if (Buffer.byteLength(value.ciphertext, 'base64url') > MAX_HPKE_CIPHERTEXT_BYTES) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['ciphertext'], message: 'HPKE ciphertext too large' });
  }
});

export type HpkeEnvelope = z.infer<typeof HpkeEnvelopeSchema>;

export interface HpkeKeyPair {
  publicKey: string;
  privateKey: string;
  keyId: string;
}

export interface HpkeEnvelopeHeader {
  direction: 'request' | 'response';
  keyId: string;
  requestId: string;
  routeHash: string;
  createdAt: string;
  expiresAt: string;
}

export async function generateHpkeKeyPair(): Promise<HpkeKeyPair> {
  const pair = await suite.kem.generateKeyPair();
  const publicKey = Buffer.from(await suite.kem.serializePublicKey(pair.publicKey)).toString('base64url');
  const privateKey = Buffer.from(await suite.kem.serializePrivateKey(pair.privateKey)).toString('base64url');
  return { publicKey, privateKey, keyId: hpkeKeyId(publicKey) };
}

export function hpkeKeyId(publicKeyB64Url: string): string {
  const key = decodeFixedKey(publicKeyB64Url, 'HPKE public key');
  return crypto.createHash('sha256').update(key).digest('hex');
}

export async function sealHpkeJson(
  recipientPublicKeyB64Url: string,
  header: HpkeEnvelopeHeader,
  plaintext: unknown,
): Promise<HpkeEnvelope> {
  const publicKeyBytes = decodeFixedKey(recipientPublicKeyB64Url, 'HPKE public key');
  if (header.keyId !== hpkeKeyId(recipientPublicKeyB64Url)) throw new Error('HPKE key id mismatch');
  validateHeaderTimes(header.createdAt, header.expiresAt, false);
  const recipientPublicKey = await suite.kem.deserializePublicKey(publicKeyBytes);
  const aad = envelopeAad(header);
  const sealed = await suite.seal(
    { recipientPublicKey, info: LATTICE_HPKE_INFO },
    Buffer.from(stableStringify(plaintext), 'utf8'),
    aad,
  );
  const envelope: HpkeEnvelope = {
    version: 1,
    suite: LATTICE_HPKE_SUITE,
    direction: header.direction,
    key_id: header.keyId,
    request_id: header.requestId,
    route_hash: normalizeRouteHash(header.routeHash),
    created_at: header.createdAt,
    expires_at: header.expiresAt,
    enc: Buffer.from(sealed.enc).toString('base64url'),
    ciphertext: Buffer.from(sealed.ct).toString('base64url'),
  };
  return HpkeEnvelopeSchema.parse(envelope);
}

export async function openHpkeJson<T>(
  recipientPrivateKeyB64Url: string,
  envelopeInput: unknown,
  now = Date.now(),
): Promise<T> {
  const envelope = HpkeEnvelopeSchema.parse(envelopeInput);
  validateHeaderTimes(envelope.created_at, envelope.expires_at, true, now);
  const privateKeyBytes = decodeFixedKey(recipientPrivateKeyB64Url, 'HPKE private key');
  const recipientPrivateKey = await suite.kem.deserializePrivateKey(privateKeyBytes);
  const aad = envelopeAad({
    direction: envelope.direction,
    keyId: envelope.key_id,
    requestId: envelope.request_id,
    routeHash: envelope.route_hash,
    createdAt: envelope.created_at,
    expiresAt: envelope.expires_at,
  });
  const plaintext = await suite.open(
    {
      recipientKey: recipientPrivateKey,
      enc: Buffer.from(envelope.enc, 'base64url'),
      info: LATTICE_HPKE_INFO,
    },
    Buffer.from(envelope.ciphertext, 'base64url'),
    aad,
  );
  return JSON.parse(Buffer.from(plaintext).toString('utf8')) as T;
}

export function parseHpkeEnvelope(input: unknown): HpkeEnvelope | null {
  const result = HpkeEnvelopeSchema.safeParse(input);
  return result.success ? result.data : null;
}

function envelopeAad(header: HpkeEnvelopeHeader): Buffer {
  return Buffer.from(stableStringify({
    version: 1,
    suite: LATTICE_HPKE_SUITE,
    direction: header.direction,
    key_id: header.keyId,
    request_id: header.requestId,
    route_hash: normalizeRouteHash(header.routeHash),
    created_at: header.createdAt,
    expires_at: header.expiresAt,
  }), 'utf8');
}

function validateHeaderTimes(createdAt: string, expiresAt: string, enforceNow: boolean, now = Date.now()): void {
  const created = new Date(createdAt).getTime();
  const expires = new Date(expiresAt).getTime();
  if (!Number.isFinite(created) || !Number.isFinite(expires) || expires <= created) {
    throw new Error('Invalid HPKE envelope validity window');
  }
  if (expires - created > 5 * 60_000) throw new Error('HPKE envelope lifetime exceeds five minutes');
  if (enforceNow && (created > now + 30_000 || expires < now)) throw new Error('HPKE envelope expired or not yet valid');
}

function normalizeRouteHash(value: string): string {
  const normalized = value.toLowerCase();
  if (!ROUTE_HASH_RE.test(normalized)) throw new Error('Invalid route metadata hash');
  return normalized.startsWith('0x') ? normalized : `0x${normalized}`;
}

function decodeFixedKey(value: string, label: string): Buffer {
  if (!B64URL_32_RE.test(value)) throw new Error(`Invalid ${label} encoding`);
  const key = Buffer.from(value, 'base64url');
  if (key.length !== 32) throw new Error(`Invalid ${label} length`);
  return key;
}
