import * as crypto from 'crypto';
import type { LatticeNodeRole } from './node-config';

export interface OverlayMessage {
  id: string;             // Unique message ID
  /** request/response: normal overlay traffic.
   *  register: hidden gateway dials relay and registers its lp:// address.
   *  register_ack: relay confirms registration.
   *  heartbeat: keepalive ping from gateway to relay.
   */
  type: 'request' | 'response' | 'register' | 'register_ack' | 'heartbeat';
  source: string;         // e.g. agent:bot1 or relay:xyz
  destination: string;    // e.g. lp://github.lattice

  // The encapsulated HTTP request/response
  payload: {
    method?: string;
    url?: string;
    headers?: Record<string, string>;
    body?: string;

    // For response
    status?: number;
  };

  // Overlay circuit trace
  trace: string[];
  auth?: {
    key_id: string;
    signature: string;
  };

  // Per-peer ECDH: sender's X25519 public key (base64 SPKI DER)
  source_pubkey?: string;
  source_node_label?: string;
  source_node_role?: LatticeNodeRole;
}

export function stableStringify(value: any): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableStringify).join(',')}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map(k => `${JSON.stringify(k)}:${stableStringify(value[k])}`).join(',')}}`;
}

function overlayAuthPayload(message: OverlayMessage): string {
  const { auth, trace, ...signed } = message;
  return stableStringify(signed);
}

// Accept either a Buffer (per-peer session key) or string (legacy shared secret)
function toHmacKey(key: Buffer | string): Buffer {
  return Buffer.isBuffer(key) ? key : Buffer.from(key, 'utf-8');
}

export function signOverlayMessage(message: OverlayMessage, key: Buffer | string): OverlayMessage {
  const signature = crypto
    .createHmac('sha256', toHmacKey(key))
    .update(overlayAuthPayload(message))
    .digest('base64');
  return { ...message, auth: { key_id: 'local-overlay', signature } };
}

export function verifyOverlayMessage(message: OverlayMessage, key: Buffer | string): boolean {
  if (!message.auth?.signature) return false;
  const expected = signOverlayMessage({ ...message, auth: undefined }, key).auth!.signature;
  try {
    return crypto.timingSafeEqual(Buffer.from(message.auth.signature), Buffer.from(expected));
  } catch {
    return false;
  }
}
