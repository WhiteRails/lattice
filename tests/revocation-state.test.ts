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

async function freshState() {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lat-revocations-'));
  homes.push(home);
  process.env.LATTICE_HOME = home;
  vi.resetModules();
  const state = await import('../node/state');
  state.initDirs();
  return { home, state };
}

describe('local revocation state', () => {
  it('uses a bounded cached set instead of reparsing on every principal check', async () => {
    const { home, state } = await freshState();
    state.saveRevocation('bot1');
    expect(state.isRevoked('bot1')).toBe(true);
    expect(state.isRevoked('bot2')).toBe(false);
    expect(state.listRevocations()).toEqual(['bot1']);
    fs.unlinkSync(path.join(home, 'revocations', 'list.json'));
    // A cached revocation cannot become permissive until the bounded refresh.
    expect(state.isRevoked('bot1')).toBe(true);
    await new Promise(resolve => setTimeout(resolve, 1_050));
    expect(state.isRevoked('bot1')).toBe(false);
  });

  it('fails closed for corrupted or oversized local revocation state', async () => {
    const { home, state } = await freshState();
    const file = path.join(home, 'revocations', 'list.json');
    fs.writeFileSync(file, JSON.stringify({ not: 'an array' }));
    expect(state.isRevoked('bot1')).toBe(true);
    fs.writeFileSync(file, JSON.stringify(Array.from({ length: 1_001 }, (_, i) => `agent${i}`)));
    process.env.LATTICE_LOCAL_REVOCATION_MAX_ENTRIES = '1000';
    expect(state.isRevoked('bot1')).toBe(true);
  });

  it('validates the local cell cardinality setting', async () => {
    const { state } = await freshState();
    expect(state.localRevocationMaxEntriesFromEnv({ LATTICE_LOCAL_REVOCATION_MAX_ENTRIES: '1000' })).toBe(1000);
    expect(() => state.localRevocationMaxEntriesFromEnv({ LATTICE_LOCAL_REVOCATION_MAX_ENTRIES: 'infinite' })).toThrow(/integer/i);
  });
});
