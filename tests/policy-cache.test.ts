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

describe('PolicyLoader cache', () => {
  it('bounds cached principals and refreshes least-recently-used entries', async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lat-policy-cache-'));
    homes.push(home);
    process.env.LATTICE_HOME = home;
    vi.resetModules();
    const { initDirs } = await import('../node/state');
    const { PolicyLoader, policyCacheMaxEntriesFromEnv } = await import('../node/policy-loader');
    initDirs();
    const loader = new PolicyLoader(1);
    loader.load('bot1');
    loader.load('bot2');
    expect(loader.cachedPolicyCount).toBe(1);
    expect(loader.check('bot1', 'lp://echo.lattice', 'ping').allowed).toBe(false);
    expect(loader.cachedPolicyCount).toBe(1);
    expect(policyCacheMaxEntriesFromEnv({ LATTICE_POLICY_CACHE_MAX_ENTRIES: '64' })).toBe(64);
    expect(() => policyCacheMaxEntriesFromEnv({ LATTICE_POLICY_CACHE_MAX_ENTRIES: 'bad' })).toThrow(/integer/i);
    loader.dispose();
  });

  it('serves repeated policy checks from memory after the first parse', async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lat-policy-cache-'));
    homes.push(home);
    process.env.LATTICE_HOME = home;
    vi.resetModules();
    const { initDirs } = await import('../node/state');
    const { PolicyLoader } = await import('../node/policy-loader');
    initDirs();
    fs.writeFileSync(path.join(home, 'policies', 'bot1.yaml'), [
      'agent: bot1', 'network:', '  default: deny', 'allow:', '  - resource: lp://echo.lattice', '    actions: [ping]', 'deny: []', 'approval_required: []', '',
    ].join('\n'));
    const loader = new PolicyLoader();
    expect(loader.check('bot1', 'lp://echo.lattice', 'ping').allowed).toBe(true);
    expect(loader.cachedPolicyCount).toBe(1);
    expect(loader.check('bot1', 'lp://echo.lattice', 'ping').allowed).toBe(true);
    loader.dispose();
    expect(loader.cachedPolicyCount).toBe(0);
  });

  it('negative-caches explicit-policy presence for portable issuer grants', async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lat-policy-presence-'));
    homes.push(home);
    process.env.LATTICE_HOME = home;
    vi.resetModules();
    const { initDirs } = await import('../node/state');
    const { PolicyLoader } = await import('../node/policy-loader');
    initDirs();
    const loader = new PolicyLoader(2);
    expect(loader.hasExplicitPolicy('portable')).toBe(false);
    expect(loader.hasExplicitPolicy('portable')).toBe(false);
    expect(loader.cachedExplicitPolicyPresenceCount).toBe(1);
    loader.dispose();
  });

  it('rejects policies whose rules, actions, or serialized source exceed cell budgets', async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lat-policy-limits-'));
    homes.push(home);
    process.env.LATTICE_HOME = home;
    vi.resetModules();
    const { initDirs } = await import('../node/state');
    const {
      PolicyLoader,
      MAX_POLICY_FILE_BYTES,
      MAX_POLICY_RULES_PER_SECTION,
      MAX_POLICY_ACTIONS_PER_RULE,
    } = await import('../node/policy-loader');
    initDirs();
    const loader = new PolicyLoader();
    expect(() => loader.save('bot1', {
      agent: 'bot1', network: { default: 'deny' }, deny: [], approval_required: [],
      allow: Array.from({ length: MAX_POLICY_RULES_PER_SECTION + 1 }, (_, index) => ({
        resource: `lp://service-${index}.lattice`, actions: ['ping'],
      })),
    })).toThrow(/allow/i);
    expect(() => loader.save('bot1', {
      agent: 'bot1', network: { default: 'deny' }, deny: [], approval_required: [],
      allow: [{
        resource: 'lp://echo.lattice',
        actions: Array.from({ length: MAX_POLICY_ACTIONS_PER_RULE + 1 }, (_, index) => `action-${index}`),
      }],
    })).toThrow(/actions/i);
    fs.writeFileSync(path.join(home, 'policies', 'bot1.yaml'), 'x'.repeat(MAX_POLICY_FILE_BYTES + 1));
    expect(() => loader.load('bot1')).toThrow(/exceeds/i);
    loader.dispose();
  });

  it('rate-limits missing-policy warnings without logging attacker-selected principals', async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lat-policy-warning-'));
    homes.push(home);
    process.env.LATTICE_HOME = home;
    vi.resetModules();
    const warning = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    const { initDirs } = await import('../node/state');
    const { PolicyLoader } = await import('../node/policy-loader');
    initDirs();
    const loader = new PolicyLoader();
    loader.load('unknown-one');
    loader.load('unknown-two');
    expect(warning).toHaveBeenCalledTimes(1);
    expect(String(warning.mock.calls[0]?.[0])).not.toContain('unknown-one');
    expect(String(warning.mock.calls[0]?.[0])).not.toContain('unknown-two');
    loader.dispose();
    warning.mockRestore();
  });
});
