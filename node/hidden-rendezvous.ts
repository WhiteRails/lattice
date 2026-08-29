import * as crypto from 'crypto';
import { z } from 'zod';
import { stableStringify } from './message';
import type { NodeCryptoBackend, NodeKeyDescriptor } from './node-crypto';

const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;
const LABEL_RE = /^[a-z0-9._-]{1,64}$/;
const KEY_ID_RE = /^[a-f0-9]{64}$/;
const NONCE_RE = /^[A-Za-z0-9_-]{32}$/;

const BaseSchema = z.object({
  version: z.literal(1),
  mode: z.enum(['hidden-submit', 'hidden-poll', 'hidden-response', 'hidden-wait']),
  token: z.string().regex(TOKEN_RE),
});

const SubmitSchema = BaseSchema.extend({
  mode: z.literal('hidden-submit'),
  gateway_label: z.string().regex(LABEL_RE),
  request: z.unknown(),
}).strict();

const WaitSchema = BaseSchema.extend({
  mode: z.literal('hidden-wait'),
  request_id: z.string().regex(/^[a-f0-9]{32}$/),
}).strict();

const GatewayBaseSchema = BaseSchema.extend({
  gateway_label: z.string().regex(LABEL_RE),
  identity_key_id: z.string().regex(KEY_ID_RE),
  timestamp: z.string().datetime({ offset: true }),
  nonce: z.string().regex(NONCE_RE),
});

const PollSchema = GatewayBaseSchema.extend({
  mode: z.literal('hidden-poll'),
  signature: z.string().regex(/^[A-Za-z0-9_-]{86}$/),
}).strict();

const ResponseSchema = GatewayBaseSchema.extend({
  mode: z.literal('hidden-response'),
  request_id: z.string().regex(/^[a-f0-9]{32}$/),
  response: z.unknown(),
  signature: z.string().regex(/^[A-Za-z0-9_-]{86}$/),
}).strict();

export const HiddenRendezvousOperationSchema = z.union([SubmitSchema, WaitSchema, PollSchema, ResponseSchema]);
export type HiddenRendezvousOperation = z.infer<typeof HiddenRendezvousOperationSchema>;
export type HiddenGatewayOperation = Extract<HiddenRendezvousOperation, { mode: 'hidden-poll' | 'hidden-response' }>;

export async function createHiddenGatewayOperation(
  mode: 'hidden-poll' | 'hidden-response',
  token: string,
  gatewayLabel: string,
  identity: NodeKeyDescriptor,
  backend: NodeCryptoBackend,
  responseFields: { request_id: string; response: unknown } | undefined = undefined,
  now = Date.now(),
): Promise<HiddenGatewayOperation> {
  const unsigned = {
    version: 1 as const,
    mode,
    token,
    gateway_label: gatewayLabel,
    identity_key_id: identity.keyId,
    timestamp: new Date(now).toISOString(),
    nonce: crypto.randomBytes(24).toString('base64url'),
    ...(mode === 'hidden-response' ? responseFields : {}),
  };
  const signature = await backend.signEd25519(identity.keyId, authPayload(unsigned));
  return HiddenRendezvousOperationSchema.parse({ ...unsigned, signature: signature.toString('base64url') }) as HiddenGatewayOperation;
}

export function verifyHiddenGatewayOperation(
  input: unknown,
  expectedIdentity: NodeKeyDescriptor,
  now = Date.now(),
): HiddenGatewayOperation {
  const operation = HiddenRendezvousOperationSchema.parse(input);
  if (operation.mode !== 'hidden-poll' && operation.mode !== 'hidden-response') {
    throw new Error('Expected authenticated hidden Gateway operation');
  }
  if (operation.identity_key_id !== expectedIdentity.keyId) throw new Error('Hidden Gateway identity mismatch');
  const timestamp = new Date(operation.timestamp).getTime();
  if (!Number.isFinite(timestamp) || Math.abs(now - timestamp) > 30_000) throw new Error('Stale hidden Gateway proof');
  const { signature, ...unsigned } = operation;
  try {
    const key = crypto.createPublicKey({
      key: Buffer.from(expectedIdentity.publicKey, 'base64'), format: 'der', type: 'spki',
    });
    if (key.asymmetricKeyType !== 'ed25519' || !crypto.verify(
      null, authPayload(unsigned), key, Buffer.from(signature, 'base64url'),
    )) throw new Error('Invalid hidden Gateway signature');
  } catch (error) {
    if (error instanceof Error && error.message === 'Invalid hidden Gateway signature') throw error;
    throw new Error('Invalid hidden Gateway identity key');
  }
  return operation;
}

function authPayload(value: object): Buffer {
  return Buffer.from(`lattice-hidden-rendezvous-v1\0${stableStringify(value)}`, 'utf8');
}
