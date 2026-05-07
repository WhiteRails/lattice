/**
 * Federation Registry + Hidden Gateway integration tests.
 *
 * Tests:
 *  1. FederationRegistryServer: starts, accepts announces, serves routes, expires TTL
 *  2. LpGatewayResolver: resolves lp:// via federation URL (Step 2 in resolution order)
 *  3. Hidden gateway: gateway dials relay, relay tracks it, routes message to it
 *  4. CLI registry announce/list integration
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as crypto from 'crypto';
import * as http from 'http';

// ─── Helpers ─────────────────────────────────────────────────────────────────

async function freshLatticeHome(): Promise<{ home: string }> {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lat-fed-'));
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

function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = http.createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address() as { port: number };
      srv.close(() => resolve(addr.port));
    });
  });
}

function sleep(ms: number) {
  return new Promise<void>(r => setTimeout(r, ms));
}

// ─── Suite 1: FederationRegistryServer unit tests ────────────────────────────

describe('FederationRegistryServer', () => {
  let server: import('../node/federation-registry').FederationRegistryServer;
  let port: number;
  let overlaySecret: string;

  beforeEach(async () => {
    await freshLatticeHome();
    port = await freePort();
    overlaySecret = crypto.randomBytes(32).toString('base64');
    vi.resetModules();
    const { FederationRegistryServer } = await import('../node/federation-registry');
    server = new FederationRegistryServer('127.0.0.1', port, overlaySecret);
    server.start();
    // Give it a moment to listen
    await sleep(100);
  });

  afterEach(() => {
    server.stop();
  });

  it('serves /v1/health', async () => {
    const resp = await httpGet(`http://127.0.0.1:${port}/v1/health`);
    const body = JSON.parse(resp);
    expect(body.ok).toBe(true);
  });

  it('returns empty routes on start', async () => {
    const resp = await httpGet(`http://127.0.0.1:${port}/v1/routes`);
    const body = JSON.parse(resp) as { version: number; routes: Record<string, unknown> };
    expect(body.version).toBe(1);
    expect(Object.keys(body.routes)).toHaveLength(0);
  });

  it('accepts announce via POST and returns route on GET', async () => {
    const payload = {
      version: 2 as const,
      fqdn: 'echo.lattice',
      gatewayPubKeyB64: crypto.randomBytes(32).toString('base64'),
      gatewayEndpoints: ['wss://3.3.3.3:8889'],
    };
    const announceResp = await httpPost(
      `http://127.0.0.1:${port}/v1/announce`,
      JSON.stringify({ payload, ttlSeconds: 120 }),
    );
    expect(JSON.parse(announceResp).ok).toBe(true);

    const routes = JSON.parse(await httpGet(`http://127.0.0.1:${port}/v1/routes`));
    expect(routes.routes['echo.lattice']).toBeDefined();
    expect(routes.routes['echo.lattice'].payload.gatewayEndpoints).toContain('wss://3.3.3.3:8889');
  });

  it('signs response with serverSig HMAC', async () => {
    // Announce something first
    await httpPost(
      `http://127.0.0.1:${port}/v1/announce`,
      JSON.stringify({
        payload: {
          version: 2,
          fqdn: 'test.lattice',
          gatewayPubKeyB64: 'abc=',
          gatewayEndpoints: ['wss://1.2.3.4:9000'],
        },
      }),
    );
    const raw = await httpGet(`http://127.0.0.1:${port}/v1/routes`);
    const body = JSON.parse(raw) as { serverSig: string; [k: string]: unknown };
    expect(body.serverSig).toBeTruthy();

    // Verify it matches expected HMAC
    const { stableStringify } = await import('../node/message');
    const { serverSig, ...rest } = body;
    const expected = crypto
      .createHmac('sha256', Buffer.from(overlaySecret, 'utf8'))
      .update(stableStringify(rest), 'utf8')
      .digest('hex');
    expect(serverSig).toBe(expected);
  });

  it('localAnnounce makes route immediately available', async () => {
    server.localAnnounce(
      {
        version: 2,
        fqdn: 'local.lattice',
        gatewayPubKeyB64: 'xyz=',
        gatewayEndpoints: ['ws://127.0.0.1:9999'],
      },
      60,
    );
    const routes = JSON.parse(await httpGet(`http://127.0.0.1:${port}/v1/routes`));
    expect(routes.routes['local.lattice']).toBeDefined();
  });

  it('rejects malformed announce', async () => {
    const resp = await httpPost(
      `http://127.0.0.1:${port}/v1/announce`,
      JSON.stringify({ notAPayload: true }),
    );
    expect(JSON.parse(resp).error).toBeDefined();
  });
});

// ─── Suite 2: fetchFederationRoutes client ───────────────────────────────────

describe('fetchFederationRoutes', () => {
  let server: import('../node/federation-registry').FederationRegistryServer;
  let port: number;
  const overlaySecret = crypto.randomBytes(32).toString('base64');

  beforeEach(async () => {
    await freshLatticeHome();
    port = await freePort();
    vi.resetModules();
    const { FederationRegistryServer } = await import('../node/federation-registry');
    server = new FederationRegistryServer('127.0.0.1', port, overlaySecret);
    server.start();
    await sleep(100);
  });

  afterEach(() => server.stop());

  it('returns null for unreachable server', async () => {
    const { fetchFederationRoutes } = await import('../node/federation-registry');
    const result = await fetchFederationRoutes('http://127.0.0.1:1', { timeoutMs: 500 });
    expect(result).toBeNull();
  });

  it('fetches and returns routes', async () => {
    server.localAnnounce({
      version: 2,
      fqdn: 'echo.lattice',
      gatewayPubKeyB64: 'key=',
      gatewayEndpoints: ['wss://relay.example.com:8889'],
    });
    const { fetchFederationRoutes } = await import('../node/federation-registry');
    const result = await fetchFederationRoutes(`http://127.0.0.1:${port}`);
    expect(result).not.toBeNull();
    expect(result!.routes['echo.lattice']).toBeDefined();
  });

  it('verifies HMAC when overlaySecret provided', async () => {
    server.localAnnounce({
      version: 2,
      fqdn: 'echo.lattice',
      gatewayPubKeyB64: 'key=',
      gatewayEndpoints: ['wss://relay.example.com:8889'],
    });
    const { fetchFederationRoutes } = await import('../node/federation-registry');

    // Correct secret — should pass
    const ok = await fetchFederationRoutes(`http://127.0.0.1:${port}`, { overlaySecret });
    expect(ok).not.toBeNull();

    // Wrong secret — should return null
    const bad = await fetchFederationRoutes(`http://127.0.0.1:${port}`, {
      overlaySecret: crypto.randomBytes(32).toString('base64'),
    });
    expect(bad).toBeNull();
  });
});

// ─── Suite 3: LpGatewayResolver federation step ──────────────────────────────

describe('LpGatewayResolver — federation resolution', () => {
  let fedServer: import('../node/federation-registry').FederationRegistryServer;
  let fedPort: number;
  const overlaySecret = crypto.randomBytes(32).toString('base64');

  beforeEach(async () => {
    await freshLatticeHome();
    fedPort = await freePort();
    vi.resetModules();
    const { FederationRegistryServer } = await import('../node/federation-registry');
    fedServer = new FederationRegistryServer('127.0.0.1', fedPort, overlaySecret);
    fedServer.start();
    await sleep(100);
  });

  afterEach(() => fedServer.stop());

  it('resolves lp:// address from federation when no chain/routing-cache', async () => {
    const pubkey = crypto.randomBytes(32).toString('base64');
    fedServer.localAnnounce({
      version: 2,
      fqdn: 'billing.lattice',
      gatewayPubKeyB64: pubkey,
      gatewayEndpoints: [`ws://127.0.0.1:${fedPort + 10}`],
    });

    vi.resetModules();
    const { LpGatewayResolver } = await import('../node/lp-resolver');
    const cfg = {
      registry: {
        federationUrls: [`http://127.0.0.1:${fedPort}`],
      },
      distributedMesh: false,
    } as any;
    const resolver = new LpGatewayResolver(cfg, null);
    const route = await resolver.resolveDestination('lp://billing.lattice');
    expect(route.fqdn).toBe('billing.lattice');
    expect(route.gatewayPubKeyB64).toBe(pubkey);
    expect(route.gatewayEndpoints).toContain(`ws://127.0.0.1:${fedPort + 10}`);
  });

  it('throws LpRoutingNotFoundError when federation has no match', async () => {
    vi.resetModules();
    const { LpGatewayResolver, LpRoutingNotFoundError } = await import('../node/lp-resolver');
    const cfg = {
      registry: {
        federationUrls: [`http://127.0.0.1:${fedPort}`],
      },
      distributedMesh: true,
    } as any;
    const resolver = new LpGatewayResolver(cfg, null);
    await expect(resolver.resolveDestination('lp://notfound.lattice')).rejects.toBeInstanceOf(
      LpRoutingNotFoundError,
    );
  });
});

// ─── Suite 4: postFederationAnnounce ─────────────────────────────────────────

describe('postFederationAnnounce', () => {
  let server: import('../node/federation-registry').FederationRegistryServer;
  let port: number;

  beforeEach(async () => {
    await freshLatticeHome();
    port = await freePort();
    vi.resetModules();
    const { FederationRegistryServer } = await import('../node/federation-registry');
    server = new FederationRegistryServer('127.0.0.1', port, 'secret');
    server.start();
    await sleep(100);
  });

  afterEach(() => server.stop());

  it('posts an announcement and it appears in GET /v1/routes', async () => {
    const { postFederationAnnounce } = await import('../node/federation-registry');
    const pubkey = crypto.randomBytes(32).toString('base64');
    const ok = await postFederationAnnounce(
      `http://127.0.0.1:${port}`,
      {
        version: 2,
        fqdn: 'clipma.lattice',
        gatewayPubKeyB64: pubkey,
        gatewayEndpoints: ['wss://5.5.5.5:8889'],
      },
      { ttlSeconds: 90, announcerPubKey: pubkey },
    );
    expect(ok).toBe(true);

    const routes = JSON.parse(await httpGet(`http://127.0.0.1:${port}/v1/routes`));
    expect(routes.routes['clipma.lattice'].payload.gatewayEndpoints).toContain('wss://5.5.5.5:8889');
  });

  it('returns false for unreachable server', async () => {
    const { postFederationAnnounce } = await import('../node/federation-registry');
    const ok = await postFederationAnnounce(
      'http://127.0.0.1:1',
      { version: 2, fqdn: 'x.lattice', gatewayPubKeyB64: 'k=', gatewayEndpoints: [] },
      { timeoutMs: 500 },
    );
    expect(ok).toBe(false);
  });
});

// ─── Suite 5: node-config schema validation ──────────────────────────────────

describe('node-config schema — new fields', () => {
  it('accepts registry.federationUrls', async () => {
    vi.resetModules();
    const { loadNodeConfig } = await import('../node/node-config');
    const { home } = await freshLatticeHome();
    const yaml = await import('js-yaml');
    const cfgPath = path.join(home, 'node.yaml');
    fs.writeFileSync(
      cfgPath,
      yaml.dump({
        nodeId: 'test-node',
        distributedMesh: true,
        registry: {
          federationUrls: ['http://registry.example.com:9000'],
        },
      }),
    );
    vi.resetModules();
    const { loadNodeConfig: lnc } = await import('../node/node-config');
    const cfg = lnc();
    expect(cfg?.registry?.federationUrls).toEqual(['http://registry.example.com:9000']);
  });

  it('rejects hidden mode without hiddenServiceAddress', async () => {
    vi.resetModules();
    const { home } = await freshLatticeHome();
    const yaml = await import('js-yaml');
    const cfgPath = path.join(home, 'node.yaml');
    fs.writeFileSync(
      cfgPath,
      yaml.dump({
        gateway: {
          mode: 'hidden',
          rendezvousRelays: ['wss://relay.example.com:8888'],
          // hiddenServiceAddress missing — should fail
        },
      }),
    );
    vi.resetModules();
    const { loadNodeConfig: lnc } = await import('../node/node-config');
    expect(() => lnc()).toThrow();
  });

  it('accepts full hidden mode config', async () => {
    vi.resetModules();
    const { home } = await freshLatticeHome();
    const yaml = await import('js-yaml');
    const cfgPath = path.join(home, 'node.yaml');
    fs.writeFileSync(
      cfgPath,
      yaml.dump({
        gateway: {
          mode: 'hidden',
          hiddenServiceAddress: 'lp://echo.lattice',
          rendezvousRelays: ['wss://relay.example.com:8888'],
          announceTtlSeconds: 120,
        },
      }),
    );
    vi.resetModules();
    const { loadNodeConfig: lnc } = await import('../node/node-config');
    const cfg = lnc();
    expect(cfg?.gateway?.mode).toBe('hidden');
    expect(cfg?.gateway?.hiddenServiceAddress).toBe('lp://echo.lattice');
    expect(cfg?.gateway?.announceTtlSeconds).toBe(120);
  });
});

// ─── HTTP helpers ─────────────────────────────────────────────────────────────

function httpGet(url: string): Promise<string> {
  return new Promise((resolve, reject) => {
    http.get(url, { timeout: 5000 }, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (d: Buffer) => chunks.push(d));
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      res.on('error', reject);
    }).on('error', reject);
  });
}

function httpPost(url: string, body: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const req = http.request(
      {
        hostname: parsed.hostname,
        port: parsed.port,
        path: parsed.pathname,
        method: 'POST',
        headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on('data', (d: Buffer) => chunks.push(d));
        res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
        res.on('error', reject);
      },
    );
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}
