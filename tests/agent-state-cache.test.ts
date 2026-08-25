import { afterEach, describe, expect, it, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const homes: string[] = [];

afterEach(() => {
  for (const home of homes.splice(0)) fs.rmSync(home, { recursive: true, force: true });
  delete process.env.LATTICE_HOME;
  vi.resetModules();
});

describe('Entry agent identity cache', () => {
  it('keeps only public identity in the hot cache and revalidates within a bounded window', async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lat-agent-cache-'));
    homes.push(home);
    process.env.LATTICE_HOME = home;
    vi.resetModules();
    const state = await import('../node/state');
    state.initDirs();
    state.saveAgent('bot1', {
      cert: {}, publicKey: 'agent-public-key', privateKey: 'agent-private-key', createdAt: new Date().toISOString(),
    });
    const identity = state.loadAgentPublicIdentity('bot1');
    expect(identity).toEqual({ publicKey: 'agent-public-key', signedCert: undefined });
    expect(identity).not.toHaveProperty('privateKey');
    fs.unlinkSync(path.join(home, 'agents', 'bot1.json'));
    expect(state.loadAgentPublicIdentity('bot1')).toEqual(identity);
    await new Promise(resolve => setTimeout(resolve, 1_050));
    expect(() => state.loadAgentPublicIdentity('bot1')).toThrow(/not found/i);
  });

  it('reuses CA material during the bounded hot window and rejects it after removal', async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lat-ca-cache-'));
    homes.push(home);
    process.env.LATTICE_HOME = home;
    vi.resetModules();
    const state = await import('../node/state');
    state.initDirs();
    state.saveCA({
      caId: 'ca.cache', publicKey: 'public', privateKey: 'private', overlaySecret: 'secret', createdAt: new Date().toISOString(),
    });
    expect(state.loadCA().overlaySecret).toBe('secret');
    fs.unlinkSync(path.join(home, 'ca', 'ca.json'));
    expect(state.loadCA().overlaySecret).toBe('secret');
    await new Promise(resolve => setTimeout(resolve, 1_050));
    expect(() => state.loadCA()).toThrow(/not initialized/i);
  });

  it('fails closed for oversized agent state and validates cache capacity configuration', async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lat-agent-cache-'));
    homes.push(home);
    process.env.LATTICE_HOME = home;
    vi.resetModules();
    const state = await import('../node/state');
    state.initDirs();
    fs.writeFileSync(path.join(home, 'agents', 'bot1.json'), 'x'.repeat(64 * 1024 + 1));
    expect(() => state.loadAgentPublicIdentity('bot1')).toThrow(/exceeds/i);
    expect(state.entryAgentCacheMaxEntriesFromEnv({ LATTICE_ENTRY_AGENT_CACHE_MAX_ENTRIES: '64' })).toBe(64);
    expect(() => state.entryAgentCacheMaxEntriesFromEnv({ LATTICE_ENTRY_AGENT_CACHE_MAX_ENTRIES: 'unbounded' })).toThrow(/integer/i);
  });
});
