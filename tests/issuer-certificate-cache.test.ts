import { describe, expect, it } from 'vitest';
import { LatticeCA } from '../core/ca';
import { generateKeyPair } from '../core/identity';
import { IssuerCertificateCache, issuerCertificateCacheMaxEntriesFromEnv } from '../node/issuer-certificate-cache';

describe('IssuerCertificateCache', () => {
  it('caches only a valid certificate bound to the configured issuer', () => {
    const issuer = new LatticeCA('issuer.example');
    const key = generateKeyPair();
    const signed = issuer.issueAgentCert({
      agent_id: 'agent:issuer:one', owner_org: 'example', agent_type: 'autonomous', version: '1', public_key: key.publicKey,
      allowed_capability_classes: [], forbidden_capability_classes: [], expires_in_days: 1,
    });
    const cache = new IssuerCertificateCache(1);
    expect(cache.verify(signed, { issuer_id: issuer.id, public_key: issuer.publicKey })?.public_key).toBe(key.publicKey);
    expect(cache.verify(signed, { issuer_id: issuer.id, public_key: issuer.publicKey })?.agent_id).toBe('agent:issuer:one');
    expect(cache.snapshot()).toEqual({ entries: 1, hits: 1, misses: 1 });
    expect(cache.verify(signed, { issuer_id: issuer.id, public_key: generateKeyPair().publicKey })).toBeNull();
    expect(issuerCertificateCacheMaxEntriesFromEnv({ LATTICE_ISSUER_CERTIFICATE_CACHE_MAX_ENTRIES: '64' })).toBe(64);
    expect(() => issuerCertificateCacheMaxEntriesFromEnv({ LATTICE_ISSUER_CERTIFICATE_CACHE_MAX_ENTRIES: 'bad' })).toThrow(/integer/i);
  });
});
