/**
 * Distributed overlay unit tests (isolate state via LATTICE_HOME + dynamic imports).
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as crypto from 'crypto';
import * as http from 'http';
import { spawn, type ChildProcessWithoutNullStreams } from 'child_process';

async function freshLatticeHome(): Promise<{ home: string }> {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lat-dist-'));
  process.env.LATTICE_HOME = home;
  vi.resetModules();
  const { initDirs, saveCA } = await import('../node/state');
  const { LatticeCA } = await import('../core/ca');
  initDirs();
  const ca = new LatticeCA('ca.test');
  saveCA({
    caId: ca.id,
    publicKey: ca.publicKey,
    privateKey: ca.privateKey,
    overlaySecret: crypto.randomBytes(32).toString('base64'),
    createdAt: new Date().toISOString(),
  });
  return { home };
}

async function configureHome(home: string, fn: () => Promise<void>): Promise<void> {
  process.env.LATTICE_HOME = home;
  vi.resetModules();
  await fn();
}

async function overlayPubkey(home: string): Promise<string> {
  let pk = '';
  await configureHome(home, async () => {
    const { getOrCreateOverlayKeyPair } = await import('../node/state');
    pk = getOrCreateOverlayKeyPair().publicKey;
  });
  return pk;
}

function spawnCli(home: string, args: string[]): ChildProcessWithoutNullStreams {
  const tsNode = path.join(process.cwd(), 'node_modules/.bin/ts-node');
  return spawn(tsNode, ['cli/lattice.ts', ...args], {
    cwd: process.cwd(),
    env: { ...process.env, LATTICE_HOME: home },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

function waitForOutput(child: ChildProcessWithoutNullStreams, pattern: RegExp): Promise<void> {
  return new Promise((resolve, reject) => {
    let seen = '';
    const timer = setTimeout(() => reject(new Error(`Timed out waiting for ${pattern}. Seen: ${seen}`)), 10_000);
    const onData = (d: Buffer) => {
      seen += d.toString();
      if (pattern.test(seen)) {
        clearTimeout(timer);
        child.stdout.off('data', onData);
        child.stderr.off('data', onData);
        resolve();
      }
    };
    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
    child.on('exit', code => {
      clearTimeout(timer);
      reject(new Error(`Process exited before ${pattern}: ${code}. Seen: ${seen}`));
    });
  });
}

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = http.createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      srv.close(() => typeof addr === 'object' && addr ? resolve(addr.port) : reject(new Error('no port')));
    });
  });
}

describe('LpGatewayResolver + routing-cache (hybrid)', () => {
  let home: string;
  let homes: string[] = [];

  beforeEach(() => {
    vi.clearAllMocks();
    homes = [];
  });

  afterEach(() => {
    for (const h of homes) {
      if (h && fs.existsSync(h)) fs.rmSync(h, { recursive: true, force: true });
    }
    if (home && fs.existsSync(home)) fs.rmSync(home, { recursive: true, force: true });
    delete process.env.LATTICE_HOME;
    vi.resetModules();
  });

  it('local fallback registry when no chain + distributedMesh off', async () => {
    ({ home } = await freshLatticeHome());
    homes.push(home);
    const { LpGatewayResolver } = await import('../node/lp-resolver');
    const { getOrCreateOverlayKeyPair } = await import('../node/state');
    const resolver = new LpGatewayResolver(null, null);
    const r = await resolver.resolveDestination('lp://echo.lattice');
    expect(r.gatewayEndpoints[0]).toBe('ws://127.0.0.1:8889');
    expect(r.gatewayPubKeyB64).toBe(getOrCreateOverlayKeyPair().publicKey);
  });

  it('routing-cache HMAC round-trip', async () => {
    ({ home } = await freshLatticeHome());
    homes.push(home);
    const { upsertRoutingPayload, readRoutingCacheFile, ROUTING_PAYLOAD_VERSION } = await import('../node/routing-cache');
    upsertRoutingPayload(null, {
      version: ROUTING_PAYLOAD_VERSION,
      fqdn: 'echo.lattice',
      gatewayNodeLabel: 'gateway-a',
      gatewayPubKeyB64: 'Zm9v',
      gatewayEndpoints: ['ws://127.0.0.1:9999'],
    });
    const disk = readRoutingCacheFile(null);
    expect(disk?.routes['echo.lattice']?.payload.gatewayEndpoints[0]).toBe('ws://127.0.0.1:9999');
  });

  it('distributedMesh on + no chain + no cache → not found', async () => {
    ({ home } = await freshLatticeHome());
    homes.push(home);
    const { saveNodeConfig } = await import('../node/node-config');
    const { LpGatewayResolver, LpRoutingNotFoundError } = await import('../node/lp-resolver');
    saveNodeConfig({ nodeId: 'relay-a', roles: ['relay'], distributedMesh: true });
    const yaml = (await import('../node/node-config')).loadNodeConfig();
    const resolver = new LpGatewayResolver(yaml, null);
    await expect(resolver.resolveDestination('lp://echo.lattice')).rejects.toThrow(LpRoutingNotFoundError);
  });

  it('imports chain-committed route bundles across different overlay secrets', async () => {
    ({ home } = await freshLatticeHome());
    homes.push(home);
    let routing = await import('../node/routing-cache');
    routing.upsertRoutingPayload(null, {
      version: routing.ROUTING_PAYLOAD_VERSION,
      fqdn: 'echo.lattice',
      gatewayNodeLabel: 'gateway-a',
      gatewayPubKeyB64: 'Zm9v',
      gatewayEndpoints: ['wss://gateway.example:8889'],
    });
    const bundle = routing.exportRoutingBundle(null, 'echo.lattice');

    ({ home } = await freshLatticeHome());
    homes.push(home);
    routing = await import('../node/routing-cache');
    routing.importRoutingBundle(null, bundle);
    const disk = routing.readRoutingCacheFile(null);
    expect(disk?.routes['echo.lattice']?.payload.gatewayNodeLabel).toBe('gateway-a');
    expect(disk?.routes['echo.lattice']?.payload.gatewayEndpoints[0]).toBe('wss://gateway.example:8889');
  });

  it('validates distributed peer labels, roles, registration, and pubkeys', async () => {
    ({ home } = await freshLatticeHome());
    homes.push(home);
    const { upsertLatticeNodeLocalRecord } = await import('../node/routing-cache');
    const { validateDistributedPeer } = await import('../node/peer-identity');

    upsertLatticeNodeLocalRecord(null, 'entry-a', {
      overlayPubKeyB64: 'Zm9v',
      roleBitmask: 1,
    });

    const baseMsg: any = {
      id: 'm1',
      type: 'request',
      source: 'bot1',
      destination: 'lp://echo.lattice',
      payload: {},
      trace: [],
      source_pubkey: 'Zm9v',
      source_node_label: 'entry-a',
      source_node_role: 'entry',
    };

    await expect(validateDistributedPeer({
      distributedMesh: true,
      cfg: null,
      chain: null,
      msg: baseMsg,
      expectedRole: 'entry',
    })).resolves.toMatchObject({ ok: true });

    await expect(validateDistributedPeer({
      distributedMesh: true,
      cfg: null,
      chain: null,
      msg: { ...baseMsg, source_node_label: undefined },
      expectedRole: 'entry',
    })).resolves.toMatchObject({ ok: false });

    await expect(validateDistributedPeer({
      distributedMesh: true,
      cfg: null,
      chain: null,
      msg: { ...baseMsg, source_node_role: 'gateway' },
      expectedRole: 'entry',
    })).resolves.toMatchObject({ ok: false });

    await expect(validateDistributedPeer({
      distributedMesh: true,
      cfg: null,
      chain: null,
      msg: { ...baseMsg, source_pubkey: 'YmFy' },
      expectedRole: 'entry',
    })).resolves.toMatchObject({ ok: false });
  });

  it('round-trips Entry → Relay → Gateway across isolated homes without shared overlaySecret', async () => {
    let relayPort: number;
    let gatewayPort: number;
    let entryPort: number;
    let backendPort: number;
    try {
      relayPort = await freePort();
      gatewayPort = await freePort();
      entryPort = await freePort();
      backendPort = await freePort();
    } catch (e: any) {
      console.warn(`Skipping socket E2E: cannot bind localhost in this environment (${e?.message ?? e})`);
      return;
    }

    const entryHome = (await freshLatticeHome()).home;
    const relayHome = (await freshLatticeHome()).home;
    const gatewayHome = (await freshLatticeHome()).home;
    homes.push(entryHome, relayHome, gatewayHome);

    const entryPk = await overlayPubkey(entryHome);
    const relayPk = await overlayPubkey(relayHome);
    const gatewayPk = await overlayPubkey(gatewayHome);

    await configureHome(entryHome, async () => {
      const { saveNodeConfig } = await import('../node/node-config');
      const { upsertLatticeNodeLocalRecord } = await import('../node/routing-cache');
      const { saveAgent, loadCA } = await import('../node/state');
      const { LatticeCA } = await import('../core/ca');
      const { generateKeyPair } = await import('../core/identity');
      saveNodeConfig({
        nodeId: 'entry-a',
        roles: ['entry'],
        distributedMesh: true,
        bind: { entry: `127.0.0.1:${entryPort}` },
        upstreamRelays: [{ label: 'relay-a', url: `ws://127.0.0.1:${relayPort}` }],
      });
      upsertLatticeNodeLocalRecord(null, 'relay-a', { overlayPubKeyB64: relayPk, roleBitmask: 2 });
      const caState = loadCA();
      const ca = LatticeCA.fromKeyPair(caState.caId, { publicKey: caState.publicKey, privateKey: caState.privateKey });
      const keys = generateKeyPair();
      const signed = ca.issueAgentCert({
        agent_id: 'agent:local:bot1',
        owner_org: 'local',
        agent_type: 'autonomous',
        version: '1.0',
        public_key: keys.publicKey,
        allowed_capability_classes: [],
        forbidden_capability_classes: [],
        expires_in_days: 365,
      });
      saveAgent('bot1', {
        cert: signed.cert,
        signedCert: signed,
        publicKey: keys.publicKey,
        privateKey: keys.privateKey,
        createdAt: new Date().toISOString(),
      });
    });

    await configureHome(relayHome, async () => {
      const { saveNodeConfig } = await import('../node/node-config');
      const { upsertLatticeNodeLocalRecord, upsertRoutingPayload, ROUTING_PAYLOAD_VERSION } = await import('../node/routing-cache');
      saveNodeConfig({
        nodeId: 'relay-a',
        roles: ['relay'],
        distributedMesh: true,
        bind: { relay: `127.0.0.1:${relayPort}` },
      });
      upsertLatticeNodeLocalRecord(null, 'entry-a', { overlayPubKeyB64: entryPk, roleBitmask: 1 });
      upsertLatticeNodeLocalRecord(null, 'gateway-a', { overlayPubKeyB64: gatewayPk, roleBitmask: 4 });
      upsertRoutingPayload(null, {
        version: ROUTING_PAYLOAD_VERSION,
        fqdn: 'echo.lattice',
        gatewayNodeLabel: 'gateway-a',
        gatewayPubKeyB64: gatewayPk,
        gatewayEndpoints: [`ws://127.0.0.1:${gatewayPort}`],
      });
    });

    await configureHome(gatewayHome, async () => {
      const { saveNodeConfig } = await import('../node/node-config');
      const { upsertLatticeNodeLocalRecord } = await import('../node/routing-cache');
      const { PolicyLoader } = await import('../node/policy-loader');
      saveNodeConfig({
        nodeId: 'gateway-a',
        roles: ['gateway'],
        distributedMesh: true,
        bind: { gateway: `127.0.0.1:${gatewayPort}` },
      });
      upsertLatticeNodeLocalRecord(null, 'relay-a', { overlayPubKeyB64: relayPk, roleBitmask: 2 });
      new PolicyLoader().grant('bot1', 'lp://echo.lattice', ['ping']);
    });

    const backend = http.createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('pong');
    });
    await new Promise<void>((resolve, reject) => {
      backend.once('error', reject);
      backend.listen(backendPort, '127.0.0.1', () => resolve());
    });

    const children: ChildProcessWithoutNullStreams[] = [];
    try {
      const gw = spawnCli(gatewayHome, ['node', 'start', '--role', 'gateway', '--service', 'lp://echo.lattice', '--target', `http://127.0.0.1:${backendPort}`]);
      children.push(gw);
      await waitForOutput(gw, /Gateway.*listening/);

      const relay = spawnCli(relayHome, ['node', 'start', '--role', 'relay']);
      children.push(relay);
      await waitForOutput(relay, /RelayNode.*Listening/);

      const entry = spawnCli(entryHome, ['node', 'start', '--role', 'entry']);
      children.push(entry);
      await waitForOutput(entry, /EntryNode.*Listening/);

      const smoke = spawnCli(entryHome, [
        'mesh',
        'smoke',
        '--agent',
        'bot1',
        '--entry',
        `http://127.0.0.1:${entryPort}`,
        '--host',
        'echo.lattice',
        '--path',
        '/ping',
        '--expect-status',
        '200',
      ]);
      let out = '';
      smoke.stdout.on('data', d => { out += d.toString(); });
      smoke.stderr.on('data', d => { out += d.toString(); });
      const code = await new Promise<number | null>(resolve => smoke.on('exit', resolve));
      expect(code, out).toBe(0);
      expect(out).toContain('pong');
    } finally {
      children.forEach(child => child.kill());
      await new Promise<void>(resolve => backend.close(() => resolve()));
    }
  }, 30_000);
});
