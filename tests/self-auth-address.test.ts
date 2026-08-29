import { describe, expect, it } from 'vitest';
import {
  deriveSelfAuthAddress,
  isSelfAuthAddress,
  isSelfAuthFqdn,
  pubkeyFromSelfAuthFqdn,
} from '../node/self-auth';
import { generateNodeKeyPair } from '../node/session';

describe('canonical Lattice identity addresses', () => {
  it('uses a DNS-safe base32 .lattice address that round-trips the X25519 key', () => {
    const key = generateNodeKeyPair().publicKey;
    const fqdn = deriveSelfAuthAddress(key);
    expect(fqdn).toMatch(/^[a-z2-7]{52}\.coral$/);
    expect(pubkeyFromSelfAuthFqdn(fqdn)).toBe(key);
    expect(isSelfAuthFqdn(fqdn)).toBe(true);
    expect(isSelfAuthAddress(`lp://${fqdn}/health`)).toBe(true);
  });

  it('does not confuse an ordinary alias or a legacy .id host with identity', () => {
    expect(isSelfAuthFqdn('echo.lattice')).toBe(false);
    expect(isSelfAuthFqdn('deadbeef.id')).toBe(false);
    expect(pubkeyFromSelfAuthFqdn(`${'a'.repeat(51)}b.lattice`)).toBeNull();
  });
});
