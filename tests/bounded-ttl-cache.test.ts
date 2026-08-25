import { afterEach, describe, expect, it, vi } from 'vitest';
import { BoundedTtlCache } from '../node/bounded-ttl-cache';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const homes: string[] = [];

afterEach(() => {
  vi.restoreAllMocks();
  for (const home of homes.splice(0)) fs.rmSync(home, { recursive: true, force: true });
  delete process.env.LATTICE_HOME;
  delete process.env.LATTICE_ROUTING_CACHE_MAX_FILE_BYTES;
  vi.resetModules();
});
import { resolverCacheOptionsFromEnv } from '../node/lp-resolver';

describe('BoundedTtlCache', () => {
  it('expires values and evicts the least recently used key at capacity', () => {
    const cache = new BoundedTtlCache<string, string>(2);
    cache.set('a', 'one', 100, 0);
    cache.set('b', 'two', 100, 0);
    expect(cache.get('a', 1)).toBe('one'); // refresh a; b is now LRU
    cache.set('c', 'three', 100, 1);
    expect(cache.get('b', 1)).toBeUndefined();
    expect(cache.get('a', 100)).toBeUndefined();
    expect(cache.get('c', 100)).toBe('three');
  });

  it('rejects cache values that would hide an unlimited chain-RPC policy', () => {
    expect(resolverCacheOptionsFromEnv({
      LATTICE_CHAIN_CACHE_TTL_MS: '5000',
      LATTICE_CHAIN_CACHE_MAX_ENTRIES: '1000',
    })).toEqual({ chainTtlMs: 5000, chainMaxEntries: 1000 });
    expect(() => resolverCacheOptionsFromEnv({ LATTICE_CHAIN_CACHE_TTL_MS: 'forever' })).toThrow(/integer/i);
  });
});

describe('routing-cache hot path', () => {
  it('reuses a verified route only until the bounded revalidation window expires', async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lat-routing-hot-'));
    homes.push(home);
    process.env.LATTICE_HOME = home;
    vi.resetModules();
    const { initDirs, saveCA } = await import('../node/state');
    const { upsertRoutingPayload, lookupRoutingPayload, routingCacheDiskPath } = await import('../node/routing-cache');
    initDirs();
    saveCA({
      caId: 'ca.routing', publicKey: 'public', privateKey: 'private',
      overlaySecret: crypto.randomBytes(32).toString('base64'), createdAt: new Date().toISOString(),
    });
    upsertRoutingPayload(null, {
      version: 2, fqdn: 'echo.lattice', gatewayPubKeyB64: 'gateway-key', gatewayEndpoints: ['ws://127.0.0.1:8889'],
    });
    expect(lookupRoutingPayload(null, 'echo.lattice')).toBeDefined();
    fs.unlinkSync(routingCacheDiskPath(null));
    // The verified in-memory value avoids a syscall in the hot window.
    expect(lookupRoutingPayload(null, 'echo.lattice')).toBeDefined();
    await new Promise(resolve => setTimeout(resolve, 1_050));
    expect(lookupRoutingPayload(null, 'echo.lattice')).toBeUndefined();
  });

  it('rejects an oversized routing artifact before parsing it', async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lat-routing-size-'));
    homes.push(home);
    process.env.LATTICE_HOME = home;
    process.env.LATTICE_ROUTING_CACHE_MAX_FILE_BYTES = '1048576';
    vi.resetModules();
    const { initDirs, saveCA } = await import('../node/state');
    const { readRoutingCacheFile } = await import('../node/routing-cache');
    initDirs();
    saveCA({
      caId: 'ca.routing', publicKey: 'public', privateKey: 'private',
      overlaySecret: crypto.randomBytes(32).toString('base64'), createdAt: new Date().toISOString(),
    });
    const oversized = path.join(home, 'oversized-routing-cache.json');
    fs.writeFileSync(oversized, 'x'.repeat(1024 * 1024 + 1));
    expect(() => readRoutingCacheFile({ registry: { cacheFile: oversized } } as any)).toThrow(/exceeds/i);
  });
});
