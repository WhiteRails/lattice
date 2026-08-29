import { describe, expect, it } from 'vitest';
import { OnionCircuitState } from '../node/onion-circuit';
import type { CircuitPath, CircuitRelayCandidate } from '../node/circuit-selector';
import type { OnionHopKeys } from '../node/onion-handshake';

function relay(label: string, operator: string, port: number): CircuitRelayCandidate {
  return {
    label, operatorId: operator.repeat(64), endpoint: `wss://${label}.test:${port}`,
    identityPubKeyB64: Buffer.alloc(44, port).toString('base64'),
    onionPubKeyB64Url: Buffer.alloc(32, port).toString('base64url'),
  };
}

function keys(byte: number): OnionHopKeys {
  return {
    forwardKey: Buffer.alloc(32, byte), backwardKey: Buffer.alloc(32, byte + 1),
    forwardNonceSalt: Buffer.alloc(4, byte + 2), backwardNonceSalt: Buffer.alloc(4, byte + 3),
  };
}

const path: CircuitPath = {
  guard: relay('guard', '1', 1), middle: relay('middle', '2', 2), terminal: relay('exit', '3', 3),
};
const limits = {
  maxAgeSeconds: 600, maxStreams: 100, maxConcurrentStreams: 32,
  guardLifetimeDays: 30, allowSingleOperatorLoopbackTests: false, allowInsecureLoopbackTests: false,
};

describe('OnionCircuitState', () => {
  it('requires exactly three established hops and distinct link circuit ids', () => {
    expect(() => new OnionCircuitState(path, limits, 0, [1, 1, 2])).toThrow(/distinct/);
    const circuit = new OnionCircuitState(path, limits, 0, [11, 22, 33]);
    circuit.addHop(keys(1));
    circuit.addHop(keys(5));
    expect(() => circuit.openStream(1)).toThrow(/building/);
    circuit.addHop(keys(9));
    expect(circuit.openStream(1)).toBe(1);
    expect(circuit.snapshot(1).path).toEqual(['guard', 'middle', 'exit']);
  });

  it('enforces 32 concurrent streams, 100 requests and ten-minute expiry', () => {
    const circuit = new OnionCircuitState(path, limits, 0, [11, 22, 33]);
    [keys(1), keys(5), keys(9)].forEach(key => circuit.addHop(key));
    const open = Array.from({ length: 32 }, () => circuit.openStream(1));
    expect(() => circuit.openStream(1)).toThrow('ONION_STREAM_BACKPRESSURE');
    open.forEach(id => circuit.closeStream(id));
    for (let i = 32; i < 100; i++) circuit.closeStream(circuit.openStream(1));
    expect(() => circuit.openStream(1)).toThrow(/request limit/);
    expect(circuit.snapshot(1).destroyReason).toBe('request_limit');

    const expired = new OnionCircuitState(path, limits, 0, [44, 55, 66]);
    [keys(1), keys(5), keys(9)].forEach(key => expired.addHop(key));
    expect(() => expired.openStream(600_000)).toThrow(/expired/);
  });

  it('never reuses per-hop AES-GCM counters and zeroizes keys on destroy', () => {
    const original = [keys(1), keys(5), keys(9)];
    const circuit = new OnionCircuitState(path, limits, 0, [11, 22, 33]);
    original.forEach(key => circuit.addHop(key));
    expect(circuit.forwardContexts(3, 1).map(value => value.sequence)).toEqual([0n, 0n, 0n]);
    expect(circuit.forwardContexts(3, 1).map(value => value.sequence)).toEqual([1n, 1n, 1n]);
    circuit.destroy('key_rotation');
    expect(circuit.snapshot().destroyReason).toBe('key_rotation');
    expect(() => circuit.keys()).toThrow();
  });
});
