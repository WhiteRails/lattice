/**
 * node/session.ts — Per-peer ECDH session key management
 *
 * Replaces the shared HMAC overlay secret with per-peer session keys:
 *   1. Each node generates an X25519 key pair (stored in CA state)
 *   2. On first contact with a peer, ECDH + HKDF-SHA256 derives a 32-byte session key
 *   3. Session keys are cached with a configurable TTL (default 1 hour)
 */

import * as crypto from 'crypto';
import { BoundedTtlCache } from './bounded-ttl-cache';

export interface NodeKeyPair {
  publicKey: string;   // base64 X25519 public key (SPKI DER)
  privateKey: string;  // base64 X25519 private key (PKCS8 DER)
}

export const DEFAULT_SESSION_TTL_MS = 60 * 60 * 1000;
export const DEFAULT_SESSION_MAX_ENTRIES = 8_192;

export function sessionMaxEntriesFromEnv(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.LATTICE_SESSION_MAX_ENTRIES;
  if (raw === undefined || raw.trim() === '') return DEFAULT_SESSION_MAX_ENTRIES;
  if (!/^[0-9]+$/.test(raw.trim())) throw new Error('LATTICE_SESSION_MAX_ENTRIES must be an integer');
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < 32 || value > 65_536) {
    throw new Error('LATTICE_SESSION_MAX_ENTRIES must be between 32 and 65536');
  }
  return value;
}

export function generateNodeKeyPair(): NodeKeyPair {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  return {
    publicKey: (publicKey as Buffer).toString('base64'),
    privateKey: (privateKey as Buffer).toString('base64'),
  };
}

/** Accept only canonical X25519 SubjectPublicKeyInfo DER values. */
export function parseOverlayPublicKey(peerPublicKeyB64: string): crypto.KeyObject {
  if (!/^[A-Za-z0-9+/]{59}=$/.test(peerPublicKeyB64)) {
    throw new Error('Invalid X25519 overlay public key encoding');
  }
  const raw = Buffer.from(peerPublicKeyB64, 'base64');
  if (raw.length !== 44) throw new Error('Invalid X25519 overlay public key length');
  const key = crypto.createPublicKey({ key: raw, format: 'der', type: 'spki' });
  if (key.asymmetricKeyType !== 'x25519') throw new Error('Overlay public key must be X25519');
  return key;
}

export function deriveSessionKey(myPrivateKeyB64: string, peerPublicKeyB64: string): Buffer {
  const myPrivKey = crypto.createPrivateKey({
    key: Buffer.from(myPrivateKeyB64, 'base64'),
    format: 'der',
    type: 'pkcs8',
  });
  if (myPrivKey.asymmetricKeyType !== 'x25519') throw new Error('Overlay private key must be X25519');
  const peerPubKey = parseOverlayPublicKey(peerPublicKeyB64);
  const sharedSecret = crypto.diffieHellman({ privateKey: myPrivKey, publicKey: peerPubKey });
  // HKDF-SHA256: derive a 32-byte session key with a fixed info string
  const PROTOCOL_SALT = Buffer.from('lattice-ecdh-session-v1');
  return Buffer.from(crypto.hkdfSync('sha256', sharedSecret, PROTOCOL_SALT, 'lattice-overlay-v1', 32));
}

export class SessionManager {
  private readonly sessions: BoundedTtlCache<string, Buffer>;
  private readonly ttlMs: number;

  constructor(
    private myNodeId: string,
    private myPrivateKey: string,
    ttlMs = DEFAULT_SESSION_TTL_MS, // 1 hour default
    private readonly maxSessions = DEFAULT_SESSION_MAX_ENTRIES,
  ) {
    if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0) throw new Error('Session TTL must be a positive integer');
    if (!Number.isSafeInteger(maxSessions) || maxSessions < 1 || maxSessions > 65_536) {
      throw new Error('Session cache capacity must be between 1 and 65536');
    }
    this.ttlMs = ttlMs;
    this.sessions = new BoundedTtlCache(maxSessions);
  }

  get cachedSessionCount(): number {
    return this.sessions.size;
  }

  getSessionKey(peerId: string, peerPublicKey: string): Buffer {
    const now = Date.now();
    const existing = this.sessions.get(peerId, now);
    if (existing) return existing;
    const key = deriveSessionKey(this.myPrivateKey, peerPublicKey);
    this.sessions.set(peerId, key, this.ttlMs, now);
    return key;
  }

  rotateKey(peerId: string): void {
    this.sessions.delete(peerId);
  }

  hasSession(peerId: string): boolean {
    return this.sessions.get(peerId) !== undefined;
  }
}
