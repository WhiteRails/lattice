/**
 * Overlay HMAC signing key selection: symmetric shared secret vs per-peer ECDH session key.
 */
import * as crypto from 'crypto';
import type { OverlayMessage } from './message';
import type { SessionManager } from './session';
import { verifyOverlayMessage as defaultVerifyOverlayMessage } from './message';

/** Stable bucket id for ECDH caches from a peer's X25519 SPKI DER (base64). */
export function peerWireId(pubkeyB64: string): string {
  return crypto.createHash('sha256').update(pubkeyB64, 'utf8').digest('hex').slice(0, 32);
}

export function chooseOverlaySignKey(
  mgr: SessionManager,
  distributedMesh: boolean,
  overlaySecret: string,
  peerPubKeyB64: string | undefined,
): Buffer | string {
  if (!distributedMesh) return overlaySecret;
  if (!peerPubKeyB64) throw new Error('Lattice distributed mesh requires peer overlay public key');
  return mgr.getSessionKey(peerWireId(peerPubKeyB64), peerPubKeyB64);
}

export function verifyIncomingOverlayFromPeer(opts: {
  distributedMesh: boolean;
  mgr: SessionManager;
  overlaySecret: string;
  /** Trusted peer key resolved from config, route, or the node registry. */
  expectedPeerPubKeyB64?: string;
  msg: OverlayMessage;
}): boolean {
  const { distributedMesh, mgr, overlaySecret, expectedPeerPubKeyB64, msg } = opts;
  try {
    // Local/shared-secret mode must never derive a key from frame-controlled data.
    if (!distributedMesh) return defaultVerifyOverlayMessage(msg, overlaySecret);
    if (!expectedPeerPubKeyB64) return false;
    const k = mgr.getSessionKey(peerWireId(expectedPeerPubKeyB64), expectedPeerPubKeyB64);
    return defaultVerifyOverlayMessage(msg, k);
  } catch {
    return false;
  }
}
