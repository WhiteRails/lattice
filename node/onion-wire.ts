import * as crypto from 'crypto';
import { z } from 'zod';
import { ONION_CELL_BODY_BYTES } from './onion-cell';
import type { NtorCreate, NtorCreated } from './onion-handshake';
import type { LatticeNodeRole } from './node-config';
import type { NodeCryptoBackend, NodeKeyDescriptor } from './node-crypto';
import { stableStringify } from './message';

const MAGIC = Buffer.from('LTW1', 'ascii');
const LABEL_RE = /^[a-z0-9._-]{1,64}$/;
const KEY_ID_RE = /^[a-f0-9]{64}$/;
const RAW_KEY_RE = /^[A-Za-z0-9_-]{43}$/;

export enum OnionWirePayloadType {
  Create2 = 1,
  Created2 = 2,
}

const NtorCreateSchema = z.object({
  version: z.literal(1), node_id: z.string().regex(KEY_ID_RE), onion_key_id: z.string().regex(KEY_ID_RE),
  client_public_key: z.string().regex(RAW_KEY_RE), encrypted_extensions: z.string().max(4096),
  extensions_mac: z.string().regex(RAW_KEY_RE),
}).strict();

const NtorCreatedSchema = z.object({
  version: z.literal(1), server_public_key: z.string().regex(RAW_KEY_RE),
  auth: z.string().regex(RAW_KEY_RE), encrypted_extensions: z.string().max(4096),
}).strict();

export const OnionCreate2Schema = z.object({
  version: z.literal(1), hop_index: z.number().int().min(0).max(2),
  client_label: z.string().regex(LABEL_RE), client_role: z.enum(['entry', 'relay', 'gateway']),
  circuit_id: z.number().int().min(1).max(0xffffffff),
  client_identity_key_id: z.string().regex(KEY_ID_RE),
  timestamp: z.string().datetime({ offset: true }),
  nonce: z.string().regex(/^[A-Za-z0-9_-]{32}$/),
  create: NtorCreateSchema,
  signature: z.string().regex(/^[A-Za-z0-9_-]{86}$/),
}).strict();

export const OnionCreated2Schema = z.object({
  version: z.literal(1), server_label: z.string().regex(LABEL_RE), created: NtorCreatedSchema,
}).strict();

export const OnionExtend2Schema = z.object({
  version: z.literal(1), next_label: z.string().regex(LABEL_RE), next_endpoint: z.string().url(),
  next_circuit_id: z.number().int().min(1).max(0xffffffff), hop_index: z.number().int().min(1).max(2),
  create: NtorCreateSchema,
  tls_spki_sha256: z.string().regex(/^[a-f0-9]{64}$/).optional(),
}).strict();

export const OnionExtended2Schema = z.object({
  version: z.literal(1), next_label: z.string().regex(LABEL_RE), created: NtorCreatedSchema,
}).strict();

export type OnionCreate2Payload = z.infer<typeof OnionCreate2Schema> & { create: NtorCreate };
export type OnionCreated2Payload = z.infer<typeof OnionCreated2Schema> & { created: NtorCreated };
export type OnionExtend2Payload = z.infer<typeof OnionExtend2Schema> & { create: NtorCreate };
export type OnionExtended2Payload = z.infer<typeof OnionExtended2Schema> & { created: NtorCreated };

export async function createAuthenticatedOnionCreate2(
  circuitId: number,
  hopIndex: number,
  clientLabel: string,
  clientRole: LatticeNodeRole,
  create: NtorCreate,
  identity: NodeKeyDescriptor,
  backend: NodeCryptoBackend,
  now = Date.now(),
): Promise<OnionCreate2Payload> {
  const unsigned = {
    version: 1 as const,
    hop_index: hopIndex,
    client_label: clientLabel,
    client_role: clientRole,
    circuit_id: circuitId,
    client_identity_key_id: identity.keyId,
    timestamp: new Date(now).toISOString(),
    nonce: crypto.randomBytes(24).toString('base64url'),
    create,
  };
  const signature = await backend.signEd25519(identity.keyId, create2AuthPayload(unsigned));
  return OnionCreate2Schema.parse({ ...unsigned, signature: signature.toString('base64url') }) as OnionCreate2Payload;
}

export function verifyAuthenticatedOnionCreate2(
  input: unknown,
  circuitId: number,
  expectedLabel: string,
  expectedRole: LatticeNodeRole,
  expectedIdentity: NodeKeyDescriptor,
  now = Date.now(),
): OnionCreate2Payload {
  const payload = OnionCreate2Schema.parse(input) as OnionCreate2Payload;
  if (payload.circuit_id !== circuitId || payload.client_label !== expectedLabel ||
      payload.client_role !== expectedRole || payload.client_identity_key_id !== expectedIdentity.keyId) {
    throw new Error('CREATE2 link identity mismatch');
  }
  const timestamp = new Date(payload.timestamp).getTime();
  if (!Number.isFinite(timestamp) || Math.abs(now - timestamp) > 30_000) throw new Error('Stale CREATE2 link proof');
  const { signature, ...unsigned } = payload;
  try {
    const key = crypto.createPublicKey({
      key: Buffer.from(expectedIdentity.publicKey, 'base64'), format: 'der', type: 'spki',
    });
    if (key.asymmetricKeyType !== 'ed25519' || !crypto.verify(
      null, create2AuthPayload(unsigned), key, Buffer.from(signature, 'base64url'),
    )) throw new Error('Invalid CREATE2 link signature');
  } catch (error) {
    if (error instanceof Error && error.message === 'Invalid CREATE2 link signature') throw error;
    throw new Error('Invalid CREATE2 link identity key');
  }
  return payload;
}

export function encodeOnionWirePayload(type: OnionWirePayloadType, value: unknown): Buffer {
  const json = Buffer.from(JSON.stringify(value), 'utf8');
  if (json.length > ONION_CELL_BODY_BYTES - 9) throw new Error('Onion handshake payload too large');
  const out = crypto.randomBytes(ONION_CELL_BODY_BYTES);
  MAGIC.copy(out, 0);
  out.writeUInt8(type, 4);
  out.writeUInt32BE(json.length, 5);
  json.copy(out, 9);
  return out;
}

export function decodeOnionWirePayload(input: Buffer): { type: OnionWirePayloadType; value: unknown } {
  if (input.length !== ONION_CELL_BODY_BYTES || !input.subarray(0, 4).equals(MAGIC)) {
    throw new Error('Invalid onion handshake payload');
  }
  const type = input.readUInt8(4);
  if (type !== OnionWirePayloadType.Create2 && type !== OnionWirePayloadType.Created2) {
    throw new Error('Unsupported onion handshake payload');
  }
  const length = input.readUInt32BE(5);
  if (length > input.length - 9) throw new Error('Truncated onion handshake payload');
  try {
    return { type, value: JSON.parse(input.subarray(9, 9 + length).toString('utf8')) };
  } catch {
    throw new Error('Invalid onion handshake JSON');
  }
}

function create2AuthPayload(value: object): Buffer {
  return Buffer.from(`lattice-create2-link-auth-v1\0${stableStringify(value)}`, 'utf8');
}
