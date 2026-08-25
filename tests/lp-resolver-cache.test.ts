import { beforeEach, describe, expect, it, vi } from 'vitest';

const chainGetLatticeNode = vi.hoisted(() => vi.fn());

vi.mock('../node/chain', async importOriginal => {
  const actual = await importOriginal<typeof import('../node/chain')>();
  return { ...actual, chainGetLatticeNode };
});

import { LpGatewayResolver } from '../node/lp-resolver';

describe('LpGatewayResolver chain cache', () => {
  beforeEach(() => chainGetLatticeNode.mockReset());

  it('caches positive and negative on-chain node lookups within the cell TTL', async () => {
    chainGetLatticeNode.mockResolvedValueOnce({ active: true, overlayPubKeyB64: 'trusted-key' });
    const resolver = new LpGatewayResolver(null, { rpcUrl: 'http://chain.invalid', contractAddress: '0x1' }, {
      chainTtlMs: 1_000,
      chainMaxEntries: 2,
    });
    await expect(resolver.resolveRelayPubkey('relay-a')).resolves.toBe('trusted-key');
    await expect(resolver.resolveRelayPubkey('relay-a')).resolves.toBe('trusted-key');
    expect(chainGetLatticeNode).toHaveBeenCalledTimes(1);

    chainGetLatticeNode.mockResolvedValueOnce(null);
    await expect(resolver.resolveRelayPubkey('unknown-relay')).resolves.toBeUndefined();
    await expect(resolver.resolveRelayPubkey('unknown-relay')).resolves.toBeUndefined();
    expect(chainGetLatticeNode).toHaveBeenCalledTimes(2);
  });
});
