import * as crypto from 'crypto';
import {
  ONION_HOPS,
  StrictSequence,
  type OnionLayerContext,
} from './onion-cell';
import type { OnionHopKeys } from './onion-handshake';
import type { CircuitPath } from './circuit-selector';
import type { OnionCircuitConfig } from './node-config';

export type OnionCircuitDestroyReason =
  | 'expired'
  | 'request_limit'
  | 'stream_limit'
  | 'protocol_error'
  | 'peer_failure'
  | 'key_rotation'
  | 'revoked'
  | 'closed';

export interface OnionCircuitSnapshot {
  id: string;
  state: 'building' | 'ready' | 'destroyed';
  path: [string, string, string];
  linkCircuitIds: [number, number, number];
  ageMs: number;
  requests: number;
  activeStreams: number;
  destroyReason?: OnionCircuitDestroyReason;
}

/**
 * Security-critical client-side circuit state. It owns all sequence numbers;
 * callers never supply a nonce counter and therefore cannot accidentally
 * reuse an AES-GCM nonce. A destroyed circuit is permanently unusable.
 */
export class OnionCircuitState {
  readonly id = crypto.randomBytes(16).toString('hex');
  readonly linkCircuitIds: [number, number, number];
  private state: OnionCircuitSnapshot['state'] = 'building';
  private hopKeys: OnionHopKeys[] = [];
  private readonly forwardSequences = [new StrictSequence(), new StrictSequence(), new StrictSequence()];
  private readonly backwardSequences = [new StrictSequence(), new StrictSequence(), new StrictSequence()];
  private readonly streams = new Set<number>();
  private requests = 0;
  private destroyReason?: OnionCircuitDestroyReason;
  private nextStreamId = 1;

  constructor(
    readonly path: CircuitPath,
    private readonly limits: OnionCircuitConfig,
    private readonly createdAt = Date.now(),
    circuitIds: readonly number[] = uniqueCircuitIds(),
  ) {
    if (circuitIds.length !== ONION_HOPS || new Set(circuitIds).size !== ONION_HOPS ||
        circuitIds.some(id => !Number.isInteger(id) || id < 1 || id > 0xffffffff)) {
      throw new Error('Each onion link requires a distinct non-zero circuit id');
    }
    this.linkCircuitIds = [...circuitIds] as [number, number, number];
  }

  addHop(keys: OnionHopKeys): void {
    this.assertState('building');
    if (this.hopKeys.length >= ONION_HOPS) return this.destroyAndThrow('protocol_error', 'Circuit has too many hops');
    validateHopKeys(keys);
    this.hopKeys.push(cloneHopKeys(keys));
    if (this.hopKeys.length === ONION_HOPS) this.state = 'ready';
  }

  openStream(now = Date.now()): number {
    this.assertUsable(now);
    if (this.requests >= this.limits.maxStreams) {
      return this.destroyAndThrow('request_limit', 'Onion circuit request limit reached');
    }
    if (this.streams.size >= this.limits.maxConcurrentStreams) {
      throw new Error('ONION_STREAM_BACKPRESSURE');
    }
    const streamId = this.allocateStreamId();
    this.streams.add(streamId);
    this.requests++;
    return streamId;
  }

  closeStream(streamId: number): void {
    if (!this.streams.delete(streamId)) throw new Error('Unknown onion stream');
  }

  forwardContexts(depth = ONION_HOPS, now = Date.now()): OnionLayerContext[] {
    this.assertDepth(depth, now);
    return this.forwardSequences.slice(0, depth).map((sequence, hop) => ({
      circuitId: this.linkCircuitIds[hop]!, sequence: sequence.issue(),
    }));
  }

  backwardContexts(depth = ONION_HOPS, now = Date.now()): OnionLayerContext[] {
    this.assertDepth(depth, now);
    return this.backwardSequences.slice(0, depth).map((sequence, hop) => ({
      circuitId: this.linkCircuitIds[hop]!, sequence: sequence.issue(),
    }));
  }

  keys(depth = ONION_HOPS): readonly OnionHopKeys[] {
    if (!Number.isInteger(depth) || depth < 1 || depth > this.hopKeys.length) throw new Error('Invalid established circuit depth');
    return this.hopKeys.slice(0, depth).map(cloneHopKeys);
  }

  destroy(reason: OnionCircuitDestroyReason): void {
    if (this.state === 'destroyed') return;
    this.state = 'destroyed';
    this.destroyReason = reason;
    this.streams.clear();
    for (const keys of this.hopKeys) {
      keys.forwardKey.fill(0);
      keys.backwardKey.fill(0);
      keys.forwardNonceSalt.fill(0);
      keys.backwardNonceSalt.fill(0);
    }
    this.hopKeys = [];
  }

  shouldRebuild(now = Date.now()): boolean {
    return this.state === 'destroyed' || now - this.createdAt >= this.limits.maxAgeSeconds * 1_000 ||
      this.requests >= this.limits.maxStreams;
  }

  snapshot(now = Date.now()): OnionCircuitSnapshot {
    return {
      id: this.id,
      state: this.state,
      path: [this.path.guard.label, this.path.middle.label, this.path.terminal.label],
      linkCircuitIds: [...this.linkCircuitIds],
      ageMs: Math.max(0, now - this.createdAt),
      requests: this.requests,
      activeStreams: this.streams.size,
      destroyReason: this.destroyReason,
    };
  }

  private assertDepth(depth: number, now: number): void {
    if (!Number.isInteger(depth) || depth < 1 || depth > ONION_HOPS || depth > this.hopKeys.length) {
      throw new Error('Invalid established circuit depth');
    }
    if (depth === ONION_HOPS) this.assertUsable(now); else this.assertState('building');
  }

  private assertUsable(now: number): void {
    this.assertState('ready');
    if (now - this.createdAt >= this.limits.maxAgeSeconds * 1_000) {
      return this.destroyAndThrow('expired', 'Onion circuit expired');
    }
  }

  private assertState(expected: OnionCircuitSnapshot['state']): void {
    if (this.state !== expected) throw new Error(`Onion circuit is ${this.state}, expected ${expected}`);
  }

  private allocateStreamId(): number {
    for (let attempts = 0; attempts < 0xffffffff; attempts++) {
      const id = this.nextStreamId;
      this.nextStreamId = this.nextStreamId === 0xffffffff ? 1 : this.nextStreamId + 1;
      if (!this.streams.has(id)) return id;
    }
    throw new Error('Onion stream id space exhausted');
  }

  private destroyAndThrow(reason: OnionCircuitDestroyReason, message: string): never {
    this.destroy(reason);
    throw new Error(message);
  }
}

function validateHopKeys(keys: OnionHopKeys): void {
  if (keys.forwardKey.length !== 32 || keys.backwardKey.length !== 32 ||
      keys.forwardNonceSalt.length !== 4 || keys.backwardNonceSalt.length !== 4) {
    throw new Error('Invalid onion hop keys');
  }
}

function cloneHopKeys(keys: OnionHopKeys): OnionHopKeys {
  validateHopKeys(keys);
  return {
    forwardKey: Buffer.from(keys.forwardKey),
    backwardKey: Buffer.from(keys.backwardKey),
    forwardNonceSalt: Buffer.from(keys.forwardNonceSalt),
    backwardNonceSalt: Buffer.from(keys.backwardNonceSalt),
  };
}

function uniqueCircuitIds(): [number, number, number] {
  const ids = new Set<number>();
  while (ids.size < ONION_HOPS) ids.add(crypto.randomInt(1, 0x1_0000_0000));
  return [...ids] as [number, number, number];
}
