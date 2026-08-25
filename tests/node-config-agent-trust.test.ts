import { afterEach, describe, expect, it, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as yaml from 'js-yaml';

const homes: string[] = [];

afterEach(() => {
  for (const home of homes.splice(0)) fs.rmSync(home, { recursive: true, force: true });
  delete process.env.LATTICE_HOME;
  vi.resetModules();
});

describe('node agent issuer trust config', () => {
  it('loads a small root set instead of per-agent identity records', async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lat-node-trust-'));
    homes.push(home);
    process.env.LATTICE_HOME = home;
    fs.writeFileSync(path.join(home, 'node.yaml'), yaml.dump({
      agentTrust: {
        issuers: [{ issuer_id: 'agents.example', public_key: '-----BEGIN PUBLIC KEY-----\nissuer\n-----END PUBLIC KEY-----' }],
      },
      gateway: {
        issuerGrants: [{
          issuer_id: 'agents.example', public_key: '-----BEGIN PUBLIC KEY-----\nissuer\n-----END PUBLIC KEY-----',
          services: [{ address: 'lp://echo.lattice', actions: ['ping'] }],
        }],
      },
    }));
    const { loadNodeConfig, resolveEntryTrustedAgentIssuers, resolveGatewayIssuerGrants } = await import('../node/node-config');
    const cfg = loadNodeConfig();
    expect(resolveEntryTrustedAgentIssuers(cfg)).toEqual([
      { issuer_id: 'agents.example', public_key: '-----BEGIN PUBLIC KEY-----\nissuer\n-----END PUBLIC KEY-----' },
    ]);
    expect(resolveGatewayIssuerGrants(cfg)).toEqual([{
      issuer_id: 'agents.example', public_key: '-----BEGIN PUBLIC KEY-----\nissuer\n-----END PUBLIC KEY-----',
      services: [{ address: 'lp://echo.lattice', actions: ['ping'] }],
    }]);
  });

  it('rejects a global-sized issuer list', async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lat-node-trust-'));
    homes.push(home);
    process.env.LATTICE_HOME = home;
    fs.writeFileSync(path.join(home, 'node.yaml'), yaml.dump({
      agentTrust: {
        issuers: Array.from({ length: 65 }, (_, index) => ({ issuer_id: `issuer-${index}`, public_key: 'x'.repeat(32) })),
      },
    }));
    const { loadNodeConfig } = await import('../node/node-config');
    expect(() => loadNodeConfig()).toThrow(/at most 64/i);
  });
});
