import { afterEach, describe, expect, it } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { spawnSync } from 'child_process';

const temporaryRoots: string[] = [];

function temporaryRoot(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'lattice-network-migration-'));
  temporaryRoots.push(root);
  return root;
}

afterEach(() => {
  for (const root of temporaryRoots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
});

describe('network state migration', () => {
  it('maps legacy lp services to L3/L4 rules without copying legacy credentials', () => {
    const root = temporaryRoot();
    const home = path.join(root, 'legacy');
    fs.mkdirSync(path.join(home, 'policies'), { recursive: true });
    fs.mkdirSync(path.join(home, 'services'), { recursive: true });
    fs.writeFileSync(
      path.join(home, 'policies', 'bot1.yaml'),
      [
        'agent: bot1',
        'allow:',
        '  - resource: lp://echo.lattice',
        '    actions: [read, write]',
        'deny:',
        '  - resource: lp://admin.lattice',
      ].join('\n'),
    );
    fs.writeFileSync(
      path.join(home, 'services', 'echo.json'),
      JSON.stringify({ address: 'lp://echo.lattice', privateKey: 'must-not-be-copied' }),
    );
    fs.writeFileSync(path.join(home, 'services', 'admin.json'), JSON.stringify({ address: 'lp://admin.lattice' }));
    const output = path.join(root, 'network-profile.json');
    const result = spawnSync(
      process.execPath,
      [
        '-r', 'ts-node/register', 'scripts/migrate-network-state.ts',
        '--lattice-home', home,
        '--agent', 'bot1',
        '--organization', 'example',
        '--gateway', '198.51.100.10:7443',
        '--gateway-name', 'gateway.example',
        '--gateway-pin', 'a'.repeat(64),
        '--service-tls-pin', 'b'.repeat(64),
        '--enrollment-token', 'single-use-token',
        '--out', output,
        '--terminate-tls',
      ],
      { cwd: process.cwd(), encoding: 'utf8' },
    );

    expect(result.status, result.stderr).toBe(0);
    const profile = JSON.parse(fs.readFileSync(output, 'utf8'));
    expect(profile.services).toHaveLength(2);
    expect(profile.services.map((service: { fqdn: string }) => service.fqdn)).toEqual(['admin.lattice', 'echo.lattice']);
    expect(profile.policy.allow).toEqual([
      expect.objectContaining({ destination: '100.96.0.2/32', protocols: ['any'], service: 'echo.lattice' }),
    ]);
    expect(profile.policy.deny).toEqual([
      expect.objectContaining({ destination: '100.96.0.1/32', protocols: ['any'], service: 'admin.lattice' }),
    ]);
    expect(profile.services.find((service: { fqdn: string }) => service.fqdn === 'echo.lattice').http_policy).toEqual({
      terminate_tls: true,
      allowed_actions: ['read', 'write'],
    });
    expect(JSON.stringify(profile)).not.toContain('must-not-be-copied');
    expect(profile.client_spki_sha256).toBe('0'.repeat(64));
    expect(profile.control_plane_key_b64).toBe(Buffer.alloc(32).toString('base64'));
    expect(fs.statSync(output).mode & 0o777).toBe(0o600);
  });
});
