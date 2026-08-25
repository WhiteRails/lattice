import * as crypto from 'crypto';
import { z } from 'zod';
import type { LatticeNodeRole } from './node-config';

export const MAX_OVERLAY_FRAME_BYTES = 1_048_576;
export const MAX_OVERLAY_DEPTH = 32;

export interface AgentProof {
  /** Canonical local agent name, independently signed by the agent key. */
  agent: string;
  /** Ed25519 public key pinned in the gateway policy for this agent. */
  public_key: string;
  signature: string;
  timestamp: string;
  nonce: string;
  body_hash: string;
  host: string;
}

export interface OverlayMessage {
  id: string;
  type: 'request' | 'response' | 'register' | 'register_ack' | 'heartbeat';
  source: string;
  destination: string;
  payload: {
    method?: string;
    url?: string;
    headers?: Record<string, string | string[] | number>;
    body?: string;
    status?: number;
    agent_proof?: AgentProof;
  };
  trace: string[];
  auth?: {
    key_id: string;
    signature: string;
  };
  source_pubkey?: string;
  source_node_label?: string;
  source_node_role?: LatticeNodeRole;
}

const AgentProofSchema = z.object({
  agent: z.string().regex(/^[a-z0-9][a-z0-9_-]{0,63}$/),
  public_key: z.string().min(32).max(8_192),
  signature: z.string().min(8).max(1_024),
  timestamp: z.string().datetime({ offset: true }),
  nonce: z.string().regex(/^[A-Za-z0-9_-]{8,256}$/),
  body_hash: z.string().regex(/^[a-f0-9]{64}$/),
  host: z.string().min(1).max(253),
}).strict();

const HeaderValueSchema = z.union([
  z.string().max(8_192),
  z.number().finite(),
  z.array(z.string().max(8_192)).max(16),
]);

const HeaderRecordSchema = z.record(z.string().min(1).max(128), HeaderValueSchema)
  .superRefine((headers, ctx) => {
    if (Object.keys(headers).length > 100) {
      ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'Too many headers' });
    }
  });

const OverlayMessageSchema = z.object({
  id: z.string().min(1).max(128),
  type: z.enum(['request', 'response', 'register', 'register_ack', 'heartbeat']),
  source: z.string().min(1).max(512),
  destination: z.string().min(1).max(512),
  payload: z.object({
    method: z.string().min(1).max(16).optional(),
    url: z.string().min(1).max(4_096).optional(),
    headers: HeaderRecordSchema.optional(),
    body: z.string().max(1_398_104).optional(),
    status: z.number().int().min(100).max(599).optional(),
    agent_proof: AgentProofSchema.optional(),
  }).strict(),
  trace: z.array(z.string().min(1).max(128)).max(16),
  auth: z.object({
    key_id: z.string().min(1).max(128),
    signature: z.string().min(1).max(512),
  }).strict().optional(),
  // A base64 X25519 SPKI DER value is exactly 44 bytes / 60 base64 chars.
  source_pubkey: z.string().regex(/^[A-Za-z0-9+/]{59}=$/).optional(),
  source_node_label: z.string().regex(/^[a-z0-9._-]{1,64}$/).optional(),
  source_node_role: z.enum(['entry', 'relay', 'gateway']).optional(),
}).strict();

export function parseOverlayMessage(raw: string): OverlayMessage | null {
  if (Buffer.byteLength(raw, 'utf8') > MAX_OVERLAY_FRAME_BYTES) return null;
  try {
    const parsed = JSON.parse(raw);
    const result = OverlayMessageSchema.safeParse(parsed);
    return result.success ? result.data : null;
  } catch {
    return null;
  }
}

/** Canonical JSON with a bounded recursion budget for signing untrusted data. */
export function stableStringify(value: unknown, depth = 0): string {
  if (depth > MAX_OVERLAY_DEPTH) throw new Error('Canonical JSON exceeds maximum depth');
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) {
    if (value.length > 1_024) throw new Error('Canonical JSON array exceeds maximum length');
    return `[${value.map(item => stableStringify(item, depth + 1)).join(',')}]`;
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  if (keys.length > 1_024) throw new Error('Canonical JSON object exceeds maximum key count');
  return `{${keys.map(k => `${JSON.stringify(k)}:${stableStringify(record[k], depth + 1)}`).join(',')}}`;
}

function overlayAuthPayload(message: OverlayMessage): string {
  // Trace entries are intentionally mutable hop metadata, never authority.
  const { auth, trace, ...signed } = message;
  return stableStringify(signed);
}

function toHmacKey(key: Buffer | string): Buffer {
  return Buffer.isBuffer(key) ? key : Buffer.from(key, 'utf8');
}

export function signOverlayMessage(message: OverlayMessage, key: Buffer | string): OverlayMessage {
  const signature = crypto
    .createHmac('sha256', toHmacKey(key))
    .update(overlayAuthPayload(message), 'utf8')
    .digest('base64');
  return { ...message, auth: { key_id: 'local-overlay', signature } };
}

export function verifyOverlayMessage(message: OverlayMessage, key: Buffer | string): boolean {
  try {
    if (!message.auth?.signature) return false;
    const provided = Buffer.from(message.auth.signature, 'base64');
    const expected = Buffer.from(
      signOverlayMessage({ ...message, auth: undefined }, key).auth!.signature,
      'base64',
    );
    return provided.length === expected.length && crypto.timingSafeEqual(provided, expected);
  } catch {
    return false;
  }
}
