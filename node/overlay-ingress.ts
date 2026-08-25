/**
 * Bounded admission for work received from untrusted overlay WebSocket peers.
 *
 * This is deliberately separate from outbound pooling: a remote peer must not
 * be able to create unbounded async routing, policy, or backend work merely by
 * keeping one socket open. Rejection is fail-fast so callers can retry against
 * another cell instead of accumulating a queue in memory.
 */
export interface OverlayIngressLimits {
  maxGlobal?: number;
  maxPerPeer?: number;
  maxGlobalBytes?: number;
  maxPerPeerBytes?: number;
}

export const DEFAULT_MAX_OVERLAY_INGRESS_GLOBAL = 4_096;
export const DEFAULT_MAX_OVERLAY_INGRESS_PER_PEER = 128;
export const DEFAULT_MAX_OVERLAY_INGRESS_GLOBAL_BYTES = 64 * 1024 * 1024;
export const DEFAULT_MAX_OVERLAY_INGRESS_PER_PEER_BYTES = 8 * 1024 * 1024;
const MIN_MAX_OVERLAY_INGRESS_GLOBAL = 32;
const HARD_MAX_OVERLAY_INGRESS_GLOBAL = 65_536;
const HARD_MAX_OVERLAY_INGRESS_PER_PEER = 8_192;
const MIN_MAX_OVERLAY_INGRESS_BYTES = 1 * 1024 * 1024;
const HARD_MAX_OVERLAY_INGRESS_GLOBAL_BYTES = 1024 * 1024 * 1024;
const HARD_MAX_OVERLAY_INGRESS_PER_PEER_BYTES = 64 * 1024 * 1024;

export class OverlayIngressLimiter {
  private readonly perPeer = new WeakMap<object, { count: number; bytes: number; weightCounts: Map<number, number> }>();
  private total = 0;
  private totalBytes = 0;
  private _rejected = 0;
  private readonly maxGlobal: number;
  private readonly maxPerPeer: number;
  private readonly maxGlobalBytes: number;
  private readonly maxPerPeerBytes: number;

  constructor(limits: OverlayIngressLimits = {}) {
    this.maxGlobal = validLimit(limits.maxGlobal, DEFAULT_MAX_OVERLAY_INGRESS_GLOBAL, 'maxGlobal');
    this.maxPerPeer = validLimit(limits.maxPerPeer, DEFAULT_MAX_OVERLAY_INGRESS_PER_PEER, 'maxPerPeer');
    this.maxGlobalBytes = validLimit(limits.maxGlobalBytes, DEFAULT_MAX_OVERLAY_INGRESS_GLOBAL_BYTES, 'maxGlobalBytes');
    this.maxPerPeerBytes = validLimit(limits.maxPerPeerBytes, DEFAULT_MAX_OVERLAY_INGRESS_PER_PEER_BYTES, 'maxPerPeerBytes');
    if (this.maxPerPeer > this.maxGlobal) {
      throw new Error('maxPerPeer cannot exceed maxGlobal');
    }
    if (this.maxPerPeerBytes > this.maxGlobalBytes) throw new Error('maxPerPeerBytes cannot exceed maxGlobalBytes');
  }

  get inFlight(): number { return this.total; }
  get inFlightBytes(): number { return this.totalBytes; }
  get rejected(): number { return this._rejected; }

  snapshot(): { inFlight: number; inFlightBytes: number; rejected: number; maxInFlight: number; maxInFlightBytes: number } {
    return {
      inFlight: this.total,
      inFlightBytes: this.totalBytes,
      rejected: this._rejected,
      maxInFlight: this.maxGlobal,
      maxInFlightBytes: this.maxGlobalBytes,
    };
  }

  tryAcquire(peer: object, bytes = 1): boolean {
    if (!Number.isSafeInteger(bytes) || bytes <= 0) throw new Error('overlay frame bytes must be a positive safe integer');
    const peerInFlight = this.perPeer.get(peer) ?? { count: 0, bytes: 0, weightCounts: new Map<number, number>() };
    if (
      this.total >= this.maxGlobal || peerInFlight.count >= this.maxPerPeer ||
      this.totalBytes + bytes > this.maxGlobalBytes || peerInFlight.bytes + bytes > this.maxPerPeerBytes
    ) {
      this._rejected++;
      return false;
    }
    this.total++;
    this.totalBytes += bytes;
    peerInFlight.count++;
    peerInFlight.bytes += bytes;
    peerInFlight.weightCounts.set(bytes, (peerInFlight.weightCounts.get(bytes) ?? 0) + 1);
    this.perPeer.set(peer, peerInFlight);
    return true;
  }

  release(peer: object, bytes = 1): void {
    const peerInFlight = this.perPeer.get(peer);
    // A caller bug must not turn capacity negative and permit unlimited work.
    const weightCount = peerInFlight?.weightCounts.get(bytes) ?? 0;
    if (!Number.isSafeInteger(bytes) || bytes <= 0 || !peerInFlight || weightCount < 1 || peerInFlight.count <= 0 || peerInFlight.bytes < bytes || this.total <= 0 || this.totalBytes < bytes) return;
    this.total--;
    this.totalBytes -= bytes;
    if (peerInFlight.count === 1) this.perPeer.delete(peer);
    else {
      peerInFlight.count--;
      peerInFlight.bytes -= bytes;
      if (weightCount === 1) peerInFlight.weightCounts.delete(bytes);
      else peerInFlight.weightCounts.set(bytes, weightCount - 1);
      this.perPeer.set(peer, peerInFlight);
    }
  }

  peerInFlight(peer: object): number {
    return this.perPeer.get(peer)?.count ?? 0;
  }
}

/**
 * Per-cell tuning. Invalid values fail at startup rather than silently turning
 * a capacity guard into an unbounded queue.
 */
export function overlayIngressLimitsFromEnv(env: NodeJS.ProcessEnv = process.env): OverlayIngressLimits {
  const maxGlobal = configuredLimit(
    env.LATTICE_OVERLAY_MAX_INFLIGHT,
    DEFAULT_MAX_OVERLAY_INGRESS_GLOBAL,
    MIN_MAX_OVERLAY_INGRESS_GLOBAL,
    HARD_MAX_OVERLAY_INGRESS_GLOBAL,
    'LATTICE_OVERLAY_MAX_INFLIGHT',
  );
  const maxPerPeer = configuredLimit(
    env.LATTICE_OVERLAY_MAX_INFLIGHT_PER_PEER,
    DEFAULT_MAX_OVERLAY_INGRESS_PER_PEER,
    1,
    HARD_MAX_OVERLAY_INGRESS_PER_PEER,
    'LATTICE_OVERLAY_MAX_INFLIGHT_PER_PEER',
  );
  if (maxPerPeer > maxGlobal) {
    throw new Error('LATTICE_OVERLAY_MAX_INFLIGHT_PER_PEER cannot exceed LATTICE_OVERLAY_MAX_INFLIGHT');
  }
  const maxGlobalBytes = configuredLimit(
    env.LATTICE_OVERLAY_MAX_INFLIGHT_BYTES,
    DEFAULT_MAX_OVERLAY_INGRESS_GLOBAL_BYTES,
    MIN_MAX_OVERLAY_INGRESS_BYTES,
    HARD_MAX_OVERLAY_INGRESS_GLOBAL_BYTES,
    'LATTICE_OVERLAY_MAX_INFLIGHT_BYTES',
  );
  const maxPerPeerBytes = configuredLimit(
    env.LATTICE_OVERLAY_MAX_INFLIGHT_PER_PEER_BYTES,
    DEFAULT_MAX_OVERLAY_INGRESS_PER_PEER_BYTES,
    MIN_MAX_OVERLAY_INGRESS_BYTES,
    HARD_MAX_OVERLAY_INGRESS_PER_PEER_BYTES,
    'LATTICE_OVERLAY_MAX_INFLIGHT_PER_PEER_BYTES',
  );
  if (maxPerPeerBytes > maxGlobalBytes) {
    throw new Error('LATTICE_OVERLAY_MAX_INFLIGHT_PER_PEER_BYTES cannot exceed LATTICE_OVERLAY_MAX_INFLIGHT_BYTES');
  }
  return { maxGlobal, maxPerPeer, maxGlobalBytes, maxPerPeerBytes };
}

function validLimit(value: number | undefined, fallback: number, name: string): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved <= 0) {
    throw new Error(`${name} must be a positive safe integer`);
  }
  return resolved;
}

function configuredLimit(
  raw: string | undefined,
  fallback: number,
  min: number,
  max: number,
  name: string,
): number {
  if (raw === undefined || raw.trim() === '') return fallback;
  if (!/^[0-9]+$/.test(raw.trim())) throw new Error(`${name} must be an integer`);
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new Error(`${name} must be between ${min} and ${max}`);
  }
  return value;
}
