/**
 * node/session.ts — Per-peer ECDH session key management
 *
 * Replaces the shared HMAC overlay secret with per-peer session keys:
 *   1. Each node generates an X25519 key pair (stored in CA state)
 *   2. On first contact with a peer, ECDH + HKDF-SHA256 derives a 32-byte session key
 *   3. Session keys are cached with a configurable TTL (default 1 hour)
 */

import * as crypto from 'crypto';

export interface NodeKeyPair {
  publicKey: string;   // base64 X25519 public key (SPKI DER)
  privateKey: string;  // base64 X25519 private key (PKCS8 DER)
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

export function deriveSessionKey(myPrivateKeyB64: string, peerPublicKeyB64: string): Buffer {
  const myPrivKey = crypto.createPrivateKey({
    key: Buffer.from(myPrivateKeyB64, 'base64'),
    format: 'der',
    type: 'pkcs8',
  });
  const peerPubKey = crypto.createPublicKey({
    key: Buffer.from(peerPublicKeyB64, 'base64'),
    format: 'der',
    type: 'spki',
  });
  const sharedSecret = crypto.diffieHellman({ privateKey: myPrivKey, publicKey: peerPubKey });
  // HKDF-SHA256: derive a 32-byte session key with a fixed info string
  const PROTOCOL_SALT = Buffer.from('lattice-ecdh-session-v1');
  return Buffer.from(crypto.hkdfSync('sha256', sharedSecret, PROTOCOL_SALT, 'lattice-overlay-v1', 32));
}

export class SessionManager {
  private sessions = new Map<string, { key: Buffer; createdAt: number }>();
  private ttlMs: number;

  constructor(
    private myNodeId: string,
    private myPrivateKey: string,
    ttlMs = 60 * 60 * 1000, // 1 hour default
  ) {
    this.ttlMs = ttlMs;
  }

  getSessionKey(peerId: string, peerPublicKey: string): Buffer {
    const existing = this.sessions.get(peerId);
    const now = Date.now();
    if (existing && now - existing.createdAt < this.ttlMs) {
      return existing.key;
    }
    const key = deriveSessionKey(this.myPrivateKey, peerPublicKey);
    this.sessions.set(peerId, { key, createdAt: now });
    return key;
  }

  rotateKey(peerId: string): void {
    this.sessions.delete(peerId);
  }

  hasSession(peerId: string): boolean {
    const existing = this.sessions.get(peerId);
    if (!existing) return false;
    return Date.now() - existing.createdAt < this.ttlMs;
  }
}
