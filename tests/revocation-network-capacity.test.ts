import { describe, expect, it } from 'vitest';
import { generateKeyPair } from '../core/identity';
import { RevocationNetwork } from '../core/revocation';

function publish(network: RevocationNetwork, target: string, privateKey: string): void {
  network.publishRevocation({
    target_type: 'AgentCert', target_hash: target, revoked_by: 'issuer', reason: 'test', issuerPrivateKey: privateKey,
  });
}

describe('RevocationNetwork shard limits', () => {
  it('fails closed at capacity and retains prior revocations', () => {
    const key = generateKeyPair();
    const network = new RevocationNetwork({ maxEntries: 1 });
    publish(network, 'first', key.privateKey);
    expect(() => publish(network, 'second', key.privateKey)).toThrow(/capacity exhausted/i);
    expect(network.isRevoked('AgentCert', 'first')).toBe(true);
    expect(network.isRevokedAnyTarget('first')).toBe(true);
    expect(network.snapshot()).toEqual({ entries: 1, maxEntries: 1 });
  });

  it('returns only a bounded shard page', () => {
    const key = generateKeyPair();
    const network = new RevocationNetwork({ maxEntries: 4, pageSize: 1 });
    publish(network, 'first', key.privateKey);
    publish(network, 'second', key.privateKey);
    expect(network.listRevocations()).toHaveLength(1);
    expect(network.listRevocations(2)).toHaveLength(2);
  });
});
