import { describe, expect, it } from 'vitest';
import { OverlayIngressLimiter, overlayIngressLimitsFromEnv } from '../node/overlay-ingress';

describe('OverlayIngressLimiter', () => {
  it('bounds concurrent work per peer and globally, then releases capacity', () => {
    const limiter = new OverlayIngressLimiter({ maxGlobal: 2, maxPerPeer: 1 });
    const first = {};
    const second = {};
    const third = {};

    expect(limiter.tryAcquire(first, 10)).toBe(true);
    expect(limiter.tryAcquire(first)).toBe(false);
    expect(limiter.tryAcquire(second, 10)).toBe(true);
    expect(limiter.tryAcquire(third)).toBe(false);
    expect(limiter.inFlight).toBe(2);
    expect(limiter.rejected).toBe(2);

    limiter.release(first, 10);
    expect(limiter.tryAcquire(third, 10)).toBe(true);
    expect(limiter.peerInFlight(first)).toBe(0);
    expect(limiter.inFlight).toBe(2);
  });

  it('bounds retained frame bytes as well as request count', () => {
    const limiter = new OverlayIngressLimiter({ maxGlobal: 10, maxPerPeer: 10, maxGlobalBytes: 10, maxPerPeerBytes: 8 });
    const first = {};
    const second = {};
    expect(limiter.tryAcquire(first, 8)).toBe(true);
    expect(limiter.tryAcquire(first, 1)).toBe(false);
    expect(limiter.tryAcquire(second, 3)).toBe(false);
    expect(limiter.inFlightBytes).toBe(8);
    limiter.release(first, 8);
    expect(limiter.tryAcquire(second, 8)).toBe(true);
  });

  it('rejects invalid limits and never underflows after repeated release', () => {
    expect(() => new OverlayIngressLimiter({ maxGlobal: 0 })).toThrow(/positive/i);
    expect(() => new OverlayIngressLimiter({ maxGlobal: 1, maxPerPeer: 2 })).toThrow(/cannot exceed/i);
    const limiter = new OverlayIngressLimiter({ maxGlobal: 1, maxPerPeer: 1 });
    const peer = {};
    limiter.release(peer);
    expect(limiter.inFlight).toBe(0);
  });

  it('releases mixed frame weights in any order without copying a per-request array', () => {
    const limiter = new OverlayIngressLimiter({ maxGlobal: 4, maxPerPeer: 4, maxGlobalBytes: 100, maxPerPeerBytes: 100 });
    const peer = {};
    expect(limiter.tryAcquire(peer, 10)).toBe(true);
    expect(limiter.tryAcquire(peer, 20)).toBe(true);
    expect(limiter.tryAcquire(peer, 10)).toBe(true);
    limiter.release(peer, 20);
    limiter.release(peer, 10);
    expect(limiter.inFlightBytes).toBe(10);
    expect(limiter.peerInFlight(peer)).toBe(1);
    limiter.release(peer, 10);
    expect(limiter.inFlight).toBe(0);
    expect(limiter.inFlightBytes).toBe(0);
  });

  it('loads bounded per-cell limits from the environment', () => {
    expect(overlayIngressLimitsFromEnv({
      LATTICE_OVERLAY_MAX_INFLIGHT: '512',
      LATTICE_OVERLAY_MAX_INFLIGHT_PER_PEER: '64',
      LATTICE_OVERLAY_MAX_INFLIGHT_BYTES: '10485760',
      LATTICE_OVERLAY_MAX_INFLIGHT_PER_PEER_BYTES: '1048576',
    })).toEqual({ maxGlobal: 512, maxPerPeer: 64, maxGlobalBytes: 10485760, maxPerPeerBytes: 1048576 });
    expect(() => overlayIngressLimitsFromEnv({
      LATTICE_OVERLAY_MAX_INFLIGHT: '64',
      LATTICE_OVERLAY_MAX_INFLIGHT_PER_PEER: '65',
    })).toThrow(/cannot exceed/i);
    expect(() => overlayIngressLimitsFromEnv({ LATTICE_OVERLAY_MAX_INFLIGHT: 'unlimited' }))
      .toThrow(/integer/i);
  });
});
