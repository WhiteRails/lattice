import * as crypto from 'crypto';
import type { OnionHopKeys } from './onion-handshake';

export const ONION_CELL_BYTES = 16_384;
export const ONION_CELL_HEADER_BYTES = 20;
export const ONION_CELL_BODY_BYTES = ONION_CELL_BYTES - ONION_CELL_HEADER_BYTES;
export const ONION_HOPS = 3;
export const ONION_AEAD_TAG_BYTES = 16;
export const ONION_INNER_BYTES = ONION_CELL_BODY_BYTES - ONION_HOPS * ONION_AEAD_TAG_BYTES;
export const ONION_STREAM_HEADER_BYTES = 12;
export const ONION_STREAM_DATA_BYTES = ONION_INNER_BYTES - ONION_STREAM_HEADER_BYTES;
const MAGIC = Buffer.from('LTO1', 'ascii');
const CONTROL_MAGIC = Buffer.from('LTC1', 'ascii');

export enum OnionCellCommand {
  Create2 = 1,
  Created2 = 2,
  Relay = 3,
  Destroy = 4,
}

export enum OnionStreamCommand {
  Begin = 1,
  Data = 2,
  End = 3,
  Sendme = 4,
  Error = 5,
}

export enum OnionControlCommand {
  Extend2 = 1,
  Extended2 = 2,
}

export type OnionDirection = 'forward' | 'backward';

export interface OnionCell {
  command: OnionCellCommand;
  flags: number;
  circuitId: number;
  sequence: bigint;
  body: Buffer;
}

export interface OnionLayerContext {
  circuitId: number;
  sequence: bigint;
}

export interface OnionStreamFragment {
  command: OnionStreamCommand;
  streamId: number;
  fragmentIndex: number;
  final: boolean;
  data: Buffer;
}

export function encodeOnionCell(cell: OnionCell): Buffer {
  if (!Number.isInteger(cell.circuitId) || cell.circuitId < 1 || cell.circuitId > 0xffffffff) {
    throw new Error('Invalid onion circuit id');
  }
  if (!Number.isInteger(cell.flags) || cell.flags < 0 || cell.flags > 0xffff) throw new Error('Invalid onion flags');
  if (cell.sequence < 0n || cell.sequence > 0xffffffffffffffffn) throw new Error('Invalid onion sequence');
  if (cell.body.length !== ONION_CELL_BODY_BYTES) throw new Error(`Onion cell body must be ${ONION_CELL_BODY_BYTES} bytes`);
  const out = Buffer.allocUnsafe(ONION_CELL_BYTES);
  MAGIC.copy(out, 0);
  out.writeUInt8(1, 4);
  out.writeUInt8(cell.command, 5);
  out.writeUInt16BE(cell.flags, 6);
  out.writeUInt32BE(cell.circuitId, 8);
  out.writeBigUInt64BE(cell.sequence, 12);
  cell.body.copy(out, ONION_CELL_HEADER_BYTES);
  return out;
}

export function decodeOnionCell(input: Buffer): OnionCell {
  if (input.length !== ONION_CELL_BYTES) throw new Error(`Onion cell must be exactly ${ONION_CELL_BYTES} bytes`);
  if (!input.subarray(0, 4).equals(MAGIC) || input.readUInt8(4) !== 1) throw new Error('Unsupported onion cell framing');
  const command = input.readUInt8(5);
  if (command < OnionCellCommand.Create2 || command > OnionCellCommand.Destroy) throw new Error('Invalid onion cell command');
  if (input.readUInt16BE(6) !== 0) throw new Error('Unsupported onion cell flags');
  const circuitId = input.readUInt32BE(8);
  if (circuitId === 0) throw new Error('Circuit id zero is reserved');
  return {
    command,
    flags: input.readUInt16BE(6),
    circuitId,
    sequence: input.readBigUInt64BE(12),
    body: Buffer.from(input.subarray(ONION_CELL_HEADER_BYTES)),
  };
}

export function encodeStreamFragment(fragment: OnionStreamFragment): Buffer {
  if (!Number.isInteger(fragment.streamId) || fragment.streamId < 1 || fragment.streamId > 0xffffffff) {
    throw new Error('Invalid onion stream id');
  }
  if (!Number.isInteger(fragment.fragmentIndex) || fragment.fragmentIndex < 0 || fragment.fragmentIndex > 0xffffffff) {
    throw new Error('Invalid onion fragment index');
  }
  if (fragment.data.length > ONION_STREAM_DATA_BYTES) throw new Error('Onion stream fragment too large');
  const out = crypto.randomBytes(ONION_INNER_BYTES);
  out.writeUInt8(fragment.command, 0);
  out.writeUInt8(fragment.final ? 1 : 0, 1);
  out.writeUInt32BE(fragment.streamId, 2);
  out.writeUInt32BE(fragment.fragmentIndex, 6);
  out.writeUInt16BE(fragment.data.length, 10);
  fragment.data.copy(out, ONION_STREAM_HEADER_BYTES);
  return out;
}

export function decodeStreamFragment(inner: Buffer): OnionStreamFragment {
  if (inner.length !== ONION_INNER_BYTES) throw new Error('Invalid onion inner payload length');
  const command = inner.readUInt8(0);
  if (command < OnionStreamCommand.Begin || command > OnionStreamCommand.Error) throw new Error('Invalid onion stream command');
  const flags = inner.readUInt8(1);
  if ((flags & ~1) !== 0) throw new Error('Invalid onion stream flags');
  const streamId = inner.readUInt32BE(2);
  if (streamId === 0) throw new Error('Onion stream id zero is reserved');
  const length = inner.readUInt16BE(10);
  if (length > ONION_STREAM_DATA_BYTES) throw new Error('Invalid onion stream data length');
  return {
    command,
    final: Boolean(flags & 1),
    streamId,
    fragmentIndex: inner.readUInt32BE(6),
    data: Buffer.from(inner.subarray(ONION_STREAM_HEADER_BYTES, ONION_STREAM_HEADER_BYTES + length)),
  };
}

export function fragmentStream(streamId: number, data: Buffer, command = OnionStreamCommand.Data): OnionStreamFragment[] {
  const fragments: OnionStreamFragment[] = [];
  const count = Math.max(1, Math.ceil(data.length / ONION_STREAM_DATA_BYTES));
  for (let index = 0; index < count; index++) {
    const start = index * ONION_STREAM_DATA_BYTES;
    fragments.push({
      command,
      streamId,
      fragmentIndex: index,
      final: index === count - 1,
      data: Buffer.from(data.subarray(start, start + ONION_STREAM_DATA_BYTES)),
    });
  }
  return fragments;
}

export function buildForwardOnion(
  inner: Buffer,
  hops: readonly OnionHopKeys[],
  contexts: readonly OnionLayerContext[],
): Buffer {
  assertThreeHops(hops, contexts);
  if (inner.length !== ONION_INNER_BYTES) throw new Error('Invalid onion inner payload length');
  return buildForwardOnionDepth(inner, hops, contexts);
}

/** Build one, two, or three layers for incremental CREATE2 -> EXTEND2. */
export function buildForwardOnionDepth(
  plaintext: Buffer,
  hops: readonly OnionHopKeys[],
  contexts: readonly OnionLayerContext[],
): Buffer {
  assertDepth(hops, contexts);
  const expected = ONION_CELL_BODY_BYTES - hops.length * ONION_AEAD_TAG_BYTES;
  if (plaintext.length !== expected) throw new Error(`Invalid onion plaintext length for depth ${hops.length}`);
  let layer: Buffer<ArrayBufferLike> = Buffer.from(plaintext);
  for (let hop = hops.length - 1; hop >= 0; hop--) {
    layer = encryptLayer(layer, hops[hop]!.forwardKey, hops[hop]!.forwardNonceSalt, 'forward', contexts[hop]!);
  }
  if (layer.length !== ONION_CELL_BODY_BYTES) throw new Error('Invalid forward onion size');
  return layer;
}

export function peelForwardLayer(
  wireBody: Buffer,
  hopIndex: number,
  keys: OnionHopKeys,
  context: OnionLayerContext,
): { meaningful: Buffer; wireBody: Buffer } {
  assertHopIndex(hopIndex);
  if (wireBody.length !== ONION_CELL_BODY_BYTES) throw new Error('Invalid onion wire body');
  const cipherLength = ONION_CELL_BODY_BYTES - hopIndex * ONION_AEAD_TAG_BYTES;
  const meaningful = decryptLayer(
    wireBody.subarray(0, cipherLength), keys.forwardKey, keys.forwardNonceSalt, 'forward', context,
  );
  const nextWire = crypto.randomBytes(ONION_CELL_BODY_BYTES);
  meaningful.copy(nextWire, 0);
  return { meaningful, wireBody: nextWire };
}

export function addBackwardLayer(
  wireBody: Buffer,
  hopIndex: number,
  keys: OnionHopKeys,
  context: OnionLayerContext,
): Buffer {
  assertHopIndex(hopIndex);
  if (wireBody.length !== ONION_CELL_BODY_BYTES) throw new Error('Invalid onion wire body');
  const plainLength = ONION_CELL_BODY_BYTES - (hopIndex + 1) * ONION_AEAD_TAG_BYTES;
  const encrypted = encryptLayer(
    wireBody.subarray(0, plainLength), keys.backwardKey, keys.backwardNonceSalt, 'backward', context,
  );
  const nextWire = crypto.randomBytes(ONION_CELL_BODY_BYTES);
  encrypted.copy(nextWire, 0);
  return nextWire;
}

export function peelBackwardOnion(
  wireBody: Buffer,
  hops: readonly OnionHopKeys[],
  contexts: readonly OnionLayerContext[],
): Buffer {
  assertThreeHops(hops, contexts);
  return peelBackwardOnionDepth(wireBody, hops, contexts);
}

export function peelBackwardOnionDepth(
  wireBody: Buffer,
  hops: readonly OnionHopKeys[],
  contexts: readonly OnionLayerContext[],
): Buffer {
  assertDepth(hops, contexts);
  if (wireBody.length !== ONION_CELL_BODY_BYTES) throw new Error('Invalid onion wire body');
  let meaningful: Buffer<ArrayBufferLike> = Buffer.from(wireBody);
  for (let hop = 0; hop < hops.length; hop++) {
    const cipherLength = ONION_CELL_BODY_BYTES - hop * ONION_AEAD_TAG_BYTES;
    meaningful = decryptLayer(
      meaningful.subarray(0, cipherLength), hops[hop]!.backwardKey, hops[hop]!.backwardNonceSalt, 'backward', contexts[hop]!,
    );
  }
  const expected = ONION_CELL_BODY_BYTES - hops.length * ONION_AEAD_TAG_BYTES;
  if (meaningful.length !== expected) throw new Error('Invalid backward onion size');
  return meaningful;
}

export function encodeOnionControl(command: OnionControlCommand, value: unknown, plaintextBytes: number): Buffer {
  if (!Number.isInteger(plaintextBytes) || plaintextBytes < 12 || plaintextBytes > ONION_CELL_BODY_BYTES) {
    throw new Error('Invalid onion control plaintext size');
  }
  const encoded = Buffer.from(JSON.stringify(value), 'utf8');
  if (encoded.length > plaintextBytes - 10) throw new Error('Onion control payload too large');
  const out = crypto.randomBytes(plaintextBytes);
  CONTROL_MAGIC.copy(out, 0);
  out.writeUInt8(1, 4);
  out.writeUInt8(command, 5);
  out.writeUInt32BE(encoded.length, 6);
  encoded.copy(out, 10);
  return out;
}

export function decodeOnionControl(plaintext: Buffer): { command: OnionControlCommand; value: unknown } | null {
  if (plaintext.length < 10 || !plaintext.subarray(0, 4).equals(CONTROL_MAGIC)) return null;
  if (plaintext.readUInt8(4) !== 1) throw new Error('Unsupported onion control version');
  const command = plaintext.readUInt8(5);
  if (command !== OnionControlCommand.Extend2 && command !== OnionControlCommand.Extended2) {
    throw new Error('Invalid onion control command');
  }
  const length = plaintext.readUInt32BE(6);
  if (length > plaintext.length - 10) throw new Error('Truncated onion control payload');
  try {
    return { command, value: JSON.parse(plaintext.subarray(10, 10 + length).toString('utf8')) };
  } catch {
    throw new Error('Invalid onion control JSON');
  }
}

export class StrictSequence {
  private next = 0n;
  claim(sequence: bigint): void {
    if (sequence !== this.next) throw new Error(`Unexpected onion sequence: got ${sequence}, expected ${this.next}`);
    this.next++;
  }
  issue(): bigint { return this.next++; }
  get value(): bigint { return this.next; }
}

function encryptLayer(
  plaintext: Buffer,
  key: Buffer,
  salt: Buffer,
  direction: OnionDirection,
  context: OnionLayerContext,
): Buffer {
  validateKeyMaterial(key, salt, context);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce(salt, context.sequence));
  cipher.setAAD(layerAad(direction, context));
  return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
}

function decryptLayer(
  ciphertext: Buffer,
  key: Buffer,
  salt: Buffer,
  direction: OnionDirection,
  context: OnionLayerContext,
): Buffer {
  validateKeyMaterial(key, salt, context);
  if (ciphertext.length < ONION_AEAD_TAG_BYTES) throw new Error('Truncated onion ciphertext');
  const body = ciphertext.subarray(0, -ONION_AEAD_TAG_BYTES);
  const tag = ciphertext.subarray(-ONION_AEAD_TAG_BYTES);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce(salt, context.sequence));
  decipher.setAAD(layerAad(direction, context));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(body), decipher.final()]);
}

function layerAad(direction: OnionDirection, context: OnionLayerContext): Buffer {
  const aad = Buffer.alloc(19);
  aad.write('LOC1', 0, 'ascii');
  aad.writeUInt8(1, 4);
  aad.writeUInt8(direction === 'forward' ? 1 : 2, 5);
  aad.writeUInt32BE(context.circuitId, 6);
  aad.writeBigUInt64BE(context.sequence, 10);
  aad.writeUInt8(OnionCellCommand.Relay, 18);
  return aad;
}

function nonce(salt: Buffer, sequence: bigint): Buffer {
  const out = Buffer.alloc(12);
  salt.copy(out, 0);
  out.writeBigUInt64BE(sequence, 4);
  return out;
}

function validateKeyMaterial(key: Buffer, salt: Buffer, context: OnionLayerContext): void {
  if (key.length !== 32 || salt.length !== 4) throw new Error('Invalid onion AEAD key material');
  if (!Number.isInteger(context.circuitId) || context.circuitId < 1 || context.circuitId > 0xffffffff) {
    throw new Error('Invalid onion layer circuit id');
  }
  if (context.sequence < 0n || context.sequence > 0xffffffffffffffffn) throw new Error('Invalid onion layer sequence');
}

function assertThreeHops(hops: readonly OnionHopKeys[], contexts: readonly OnionLayerContext[]): void {
  if (hops.length !== ONION_HOPS || contexts.length !== ONION_HOPS) throw new Error('Lattice onion circuits require exactly three hops');
}

function assertDepth(hops: readonly OnionHopKeys[], contexts: readonly OnionLayerContext[]): void {
  if (hops.length < 1 || hops.length > ONION_HOPS || contexts.length !== hops.length) {
    throw new Error('Lattice onion layer depth must be between one and three');
  }
}

function assertHopIndex(hopIndex: number): void {
  if (!Number.isInteger(hopIndex) || hopIndex < 0 || hopIndex >= ONION_HOPS) throw new Error('Invalid onion hop index');
}
