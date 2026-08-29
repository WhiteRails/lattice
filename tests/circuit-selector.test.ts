import { describe, expect, it } from 'vitest';
import { selectCircuitPath, type CircuitRelayCandidate } from '../node/circuit-selector';

function relay(label: string, operatorByte: string, port: number): CircuitRelayCandidate {
  return {
    label,
    endpoint: `wss://${label}.example:${port}`,
    operatorId: operatorByte.repeat(64),
    identityPubKeyB64: Buffer.alloc(44, port).toString('base64'),
    onionPubKeyB64Url: Buffer.alloc(32, port).toString('base64url'),
    tlsSpkiSha256: String(port % 10).repeat(64),
  };
}

describe('operator-diverse circuit selection', () => {
  it('selects exactly three labels and operators', () => {
    const path = selectCircuitPath([
      relay('guard-a', 'a', 1), relay('middle-b', 'b', 2), relay('exit-c', 'c', 3), relay('extra-d', 'd', 4),
    ], { terminalLabel: 'exit-c', guardLabels: ['guard-a'], randomInt: () => 0 });
    expect([path.guard.label, path.middle.label, path.terminal.label]).toEqual(['guard-a', 'middle-b', 'exit-c']);
    expect(new Set([path.guard.operatorId, path.middle.operatorId, path.terminal.operatorId]).size).toBe(3);
  });

  it('fails closed when three operators are unavailable', () => {
    expect(() => selectCircuitPath([
      relay('relay-a', 'a', 1), relay('relay-b', 'a', 2), relay('relay-c', 'b', 3),
    ], { randomInt: () => 0 })).toThrow(/three-operator|operator-diverse/i);
  });

  it('permits the explicit same-operator exception only on loopback', () => {
    const local = ['one', 'two', 'three'].map((label, index) => ({
      ...relay(label, 'a', index + 1), endpoint: `ws://127.0.0.1:${8000 + index}`,
    }));
    expect(() => selectCircuitPath(local, { randomInt: () => 0 })).toThrow();
    expect(selectCircuitPath(local, { randomInt: () => 0, allowSingleOperatorLoopbackTests: true })).toBeTruthy();
    expect(() => selectCircuitPath([
      relay('one', 'a', 1), relay('two', 'a', 2), relay('three', 'a', 3),
    ], { randomInt: () => 0, allowSingleOperatorLoopbackTests: true })).toThrow();
  });
});
