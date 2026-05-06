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
  peerPubFromMessage?: string;
  msg: OverlayMessage;
}): boolean {
  const { distributedMesh, mgr, overlaySecret, peerPubFromMessage, msg } = opts;
  if (!distributedMesh) {
    const k = peerPubFromMessage
      ? mgr.getSessionKey(peerWireId(peerPubFromMessage), peerPubFromMessage)
      : overlaySecret;
    return defaultVerifyOverlayMessage(msg, k);
  }
  if (!peerPubFromMessage) return false;
  const k = mgr.getSessionKey(peerWireId(peerPubFromMessage), peerPubFromMessage);
  return defaultVerifyOverlayMessage(msg, k);
}
