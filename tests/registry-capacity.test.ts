import { describe, expect, it } from 'vitest';
import { generateKeyPair } from '../core/identity';
import { LatticeRegistry } from '../core/registry';

function register(registry: LatticeRegistry, name: string, publicKey: string, org?: string): void {
  registry.register({
    name, public_key: publicKey, service_cert: 'service-cert', gateway_endpoints: ['wss://gateway.example:8889'],
    issuer: 'issuer', accepted_agent_issuers: [], linked_org_id: org,
  });
}

describe('LatticeRegistry shard limits', () => {
  it('fails closed at capacity and pages names', () => {
    const key = generateKeyPair();
    const registry = new LatticeRegistry('registry', undefined, { maxEntries: 2, pageSize: 1 });
    register(registry, 'one.lattice', key.publicKey);
    register(registry, 'two.lattice', key.publicKey);
    expect(registry.listNames()).toEqual(['one.lattice']);
    expect(registry.listNames(2)).toEqual(['one.lattice', 'two.lattice']);
    expect(() => register(registry, 'three.lattice', key.publicKey)).toThrow(/capacity exhausted/i);
    expect(registry.snapshot()).toEqual({ entries: 2, maxEntries: 2 });
  });

  it('uses the subject index for organization freeze lookup', () => {
    const key = generateKeyPair();
    const registry = new LatticeRegistry('registry', undefined, { maxEntries: 2 });
    register(registry, 'one.lattice', key.publicKey, 'org-one');
    registry.freezeSubject({
      name: 'one.lattice', reason: 'test', effect: {
        block_high_risk_actions: true,
        block_new_cert_issuance: false,
        allow_read_only_verification: true,
      }, signed_by: ['recovery'], effective_at: new Date().toISOString(),
    });
    expect(registry.isOrgHighRiskFrozen('org-one')).toBe(true);
  });
});
