import * as crypto from 'crypto';
import { z } from 'zod';
import type { AgentProof } from './message';
import { stableStringify } from './message';

const KEY_ID_RE = /^[a-f0-9]{64}$/;
const REQUEST_ID_RE = /^[a-f0-9]{32}$/;
const ROUTE_HASH_RE = /^0x[a-f0-9]{64}$/;
const X25519_RE = /^[A-Za-z0-9_-]{43}$/;

const AgentProofSchema = z.object({
  agent: z.string().regex(/^[a-z0-9][a-z0-9_-]{0,63}$/),
  public_key: z.string().min(32).max(8_192),
  signature: z.string().min(8).max(1_024),
  timestamp: z.string().datetime({ offset: true }),
  nonce: z.string().regex(/^[A-Za-z0-9_-]{8,256}$/),
  body_hash: z.string().regex(/^[a-f0-9]{64}$/),
  host: z.string().min(1).max(253),
  certificate: z.unknown().optional(),
}).strict();

const HeadersSchema = z.record(z.union([
  z.string().max(8_192),
  z.number().finite(),
  z.array(z.string().max(8_192)).max(16),
])).superRefine((headers, ctx) => {
  if (Object.keys(headers).length > 100) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: 'Too many E2E headers' });
  }
});

export const E2eRequestSchema = z.object({
  version: z.literal(1),
  request_id: z.string().regex(REQUEST_ID_RE),
  route_hash: z.string().regex(ROUTE_HASH_RE),
  source: z.string().regex(/^[a-z0-9][a-z0-9_-]{0,63}$/),
  destination: z.string().min(1).max(512),
  method: z.string().min(1).max(16),
  url: z.string().min(1).max(4_096),
  headers: HeadersSchema,
  body: z.string().max(1_398_104),
  agent_proof: AgentProofSchema,
  response_key_id: z.string().regex(KEY_ID_RE),
  response_public_key: z.string().regex(X25519_RE),
}).strict();

export type E2eRequest = z.infer<typeof E2eRequestSchema> & { agent_proof: AgentProof };

const E2eResponseUnsignedSchema = z.object({
  version: z.literal(1),
  request_id: z.string().regex(REQUEST_ID_RE),
  route_hash: z.string().regex(ROUTE_HASH_RE),
  status: z.number().int().min(100).max(599),
  headers: HeadersSchema,
  body: z.string().max(1_398_104),
  gateway_identity_key_id: z.string().regex(KEY_ID_RE),
  gateway_identity_public_key: z.string().min(32).max(8_192),
});

export const E2eResponseSchema = E2eResponseUnsignedSchema.extend({
  signature: z.string().min(1).max(512),
}).strict();

export type E2eResponseUnsigned = z.infer<typeof E2eResponseUnsignedSchema>;
export type E2eResponse = z.infer<typeof E2eResponseSchema>;

export function parseE2eRequest(value: unknown): E2eRequest {
  return E2eRequestSchema.parse(value) as E2eRequest;
}

export function parseE2eResponse(value: unknown): E2eResponse {
  return E2eResponseSchema.parse(value);
}

export function gatewayResponseSignaturePayload(value: E2eResponseUnsigned): Buffer {
  return Buffer.from(`lattice-gateway-response-v1\0${stableStringify(value)}`, 'utf8');
}

export function verifyGatewayResponse(response: E2eResponse, expectedIdentityPublicKey: string): boolean {
  try {
    if (response.gateway_identity_public_key !== expectedIdentityPublicKey) return false;
    const { signature, ...unsigned } = response;
    const publicKeyDer = Buffer.from(expectedIdentityPublicKey, 'base64');
    const keyId = crypto.createHash('sha256').update(publicKeyDer).digest('hex');
    if (keyId !== response.gateway_identity_key_id) return false;
    const publicKey = crypto.createPublicKey({ key: publicKeyDer, format: 'der', type: 'spki' });
    return crypto.verify(
      null,
      gatewayResponseSignaturePayload(unsigned),
      publicKey,
      Buffer.from(signature, 'base64url'),
    );
  } catch {
    return false;
  }
}
