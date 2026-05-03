import { describe, it, expect } from 'vitest';
import { assertValidPublicLatticeFqdn, labelToBytes32 } from '../node/chain';

describe('chain labelToBytes32', () => {
  it('hashes UTF-8 labels to deterministic bytes32', () => {
    expect(labelToBytes32('governments.lattice')).toMatch(/^0x[0-9a-f]{64}$/i);
    expect(labelToBytes32('governments.lattice')).toBe(labelToBytes32('governments.lattice'));
  });

  it('passes through raw 0x + 64 hex', () => {
    const h = '0x' + 'ab'.repeat(32);
    expect(labelToBytes32(h)).toBe(h);
  });
});

describe('assertValidPublicLatticeFqdn', () => {
  it('accepts lowercase label.lattice', () => {
    expect(() => assertValidPublicLatticeFqdn('echo.lattice')).not.toThrow();
  });

  it('rejects uppercase and wrong TLD', () => {
    expect(() => assertValidPublicLatticeFqdn('Echo.lattice')).toThrow();
    expect(() => assertValidPublicLatticeFqdn('echo.com')).toThrow();
    expect(() => assertValidPublicLatticeFqdn('a.b.lattice')).toThrow();
  });
});
