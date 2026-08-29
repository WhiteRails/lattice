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
import { stableStringify } from '../node/message';

// ─── Helpers ─────────────────────────────────────────────────────────────────

async function freshLatticeHome(): Promise<{ home: string; overlaySecret: string }> {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lat-fed-'));
  process.env.LATTICE_HOME = home;
  vi.resetModules();
  const { initDirs, saveCA } = await import('../node/state');
  const { LatticeCA } = await import('../core/ca');
  initDirs();
  const ca = new LatticeCA('ca.test');
  const overlaySecret = crypto.randomBytes(32).toString('base64');
  saveCA({
    caId: ca.id,
    publicKey: ca.publicKey,
    privateKey: ca.privateKey,
    overlaySecret,
    createdAt: new Date().toISOString(),
  });
  return { home, overlaySecret };
}

/** Compute the HMAC that POST /v1/announce requires (matches server-side logic). */
function computeAnnounceHmac(
  overlaySecret: string,
  payload: object,
  opts: { ttlSeconds?: number; announcerPubKey?: string } = {},
): string {
  const hmacBody: Record<string, unknown> = { payload };
  if (opts.ttlSeconds !== undefined) hmacBody.ttlSeconds = opts.ttlSeconds;
  if (opts.announcerPubKey !== undefined) hmacBody.announcerPubKey = opts.announcerPubKey;
  return crypto.createHmac('sha256', Buffer.from(overlaySecret, 'utf8'))
    .update(stableStringify(hmacBody), 'utf8')
    .digest('hex');
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

function overlayPubkey(): string {
  const { publicKey } = crypto.generateKeyPairSync('x25519', {
    publicKeyEncoding: { type: 'spki', format: 'der' },
    privateKeyEncoding: { type: 'pkcs8', format: 'der' },
  });
  return (publicKey as Buffer).toString('base64');
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

  it('does not expose a global route listing', async () => {
    const resp = await httpGet(`http://127.0.0.1:${port}/v1/routes`);
    const body = JSON.parse(resp) as { error: string };
    expect(body.error).toMatch(/global route listing/i);
  });

  it('accepts announce via POST and returns route on GET', async () => {
    const payload = {
      version: 2 as const,
      fqdn: 'echo.lattice',
      gatewayPubKeyB64: overlayPubkey(),
      gatewayEndpoints: ['wss://3.3.3.3:8889'],
    };
    const announceResp = await httpPost(
      `http://127.0.0.1:${port}/v1/announce`,
      JSON.stringify({
        payload,
        ttlSeconds: 120,
        announceHmac: computeAnnounceHmac(overlaySecret, payload, { ttlSeconds: 120 }),
      }),
    );
    expect(JSON.parse(announceResp).ok).toBe(true);

    const route = JSON.parse(await httpGet(`http://127.0.0.1:${port}/v1/routes/echo.lattice`));
    expect(route.route).toBeDefined();
    expect(route.route.payload.gatewayEndpoints).toContain('wss://3.3.3.3:8889');
  });

  it('rejects oversized and over-nested announces without taking down the registry', async () => {
    try {
      await httpPost(`http://127.0.0.1:${port}/v1/announce`, 'x'.repeat(65_537));
    } catch {
      // The server may reset an oversized request after rejecting its body.
    }
    let deeplyNested: unknown = {};
    for (let i = 0; i < 40; i++) deeplyNested = [deeplyNested];
    const invalid = await httpPost(
      `http://127.0.0.1:${port}/v1/announce`,
      JSON.stringify({ payload: deeplyNested }),
    );
    expect(JSON.parse(invalid).error).toBe('Invalid announce body');
    expect(JSON.parse(await httpGet(`http://127.0.0.1:${port}/v1/health`)).ok).toBe(true);
  });

  it('serves a signed single-route response without serializing the global table', async () => {
    server.localAnnounce({
      version: 2,
      fqdn: 'one.lattice',
      gatewayPubKeyB64: overlayPubkey(),
      gatewayEndpoints: ['wss://one.example:8889'],
    });
    server.localAnnounce({
      version: 2,
      fqdn: 'two.lattice',
      gatewayPubKeyB64: overlayPubkey(),
      gatewayEndpoints: ['wss://two.example:8889'],
    });
    const route = JSON.parse(await httpGet(`http://127.0.0.1:${port}/v1/routes/one.lattice`));
    expect(route.fqdn).toBe('one.lattice');
    expect(route.route.payload.fqdn).toBe('one.lattice');
    expect(route.routes).toBeUndefined();
    const { serverSig, ...body } = route;
    const expected = crypto.createHmac('sha256', Buffer.from(overlaySecret, 'utf8'))
      .update(stableStringify(body), 'utf8').digest('hex');
    expect(serverSig).toBe(expected);
  });

  it('signs a named response with serverSig HMAC', async () => {
    const payload = {
      version: 2,
      fqdn: 'test.lattice',
      gatewayPubKeyB64: overlayPubkey(),
      gatewayEndpoints: ['wss://1.2.3.4:9000'],
    };
    server.localAnnounce(payload);
    const raw = await httpGet(`http://127.0.0.1:${port}/v1/routes/test.lattice`);
    const body = JSON.parse(raw) as { serverSig: string; [k: string]: unknown };
    expect(body.serverSig).toBeTruthy();

    // Verify it matches expected HMAC (stableStringify imported at top)
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
    const route = JSON.parse(await httpGet(`http://127.0.0.1:${port}/v1/routes/local.lattice`));
    expect(route.route).toBeDefined();
  });

  it('bounds a registry shard while allowing existing names to renew', async () => {
    const { FederationRegistryServer } = await import('../node/federation-registry');
    const bounded = new FederationRegistryServer('127.0.0.1', 0, overlaySecret, undefined, { maxRoutes: 1 });
    const first = {
      version: 2 as const,
      fqdn: 'one.lattice',
      gatewayPubKeyB64: overlayPubkey(),
      gatewayEndpoints: ['wss://one.example:8889'],
    };
    bounded.localAnnounce(first, 60);
    bounded.localAnnounce({ ...first, gatewayEndpoints: ['wss://renewed.example:8889'] }, 60);
    expect(() => bounded.localAnnounce({
      ...first,
      fqdn: 'two.lattice',
      gatewayPubKeyB64: overlayPubkey(),
    }, 60)).toThrow(/capacity/i);
    expect(bounded.getRoutes().size).toBe(1);
    expect(bounded.snapshot()).toEqual({ routes: 1, expiryEntries: 1, maxRoutes: 1 });
  });

  it('removes an expired route and its indexed expiry row', async () => {
    server.localAnnounce({
      version: 2,
      fqdn: 'expired.lattice',
      gatewayPubKeyB64: overlayPubkey(),
      gatewayEndpoints: ['wss://expired.example:8889'],
    }, 1);
    expect(server.snapshot()).toMatchObject({ routes: 1, expiryEntries: 1 });
    await sleep(1_050);
    const response = JSON.parse(await httpGet(`http://127.0.0.1:${port}/v1/routes/expired.lattice`));
    expect(response.error).toBe('Route not found');
    expect(server.snapshot()).toMatchObject({ routes: 0, expiryEntries: 0 });
  });

  it('rejects malformed announce', async () => {
    const resp = await httpPost(
      `http://127.0.0.1:${port}/v1/announce`,
      JSON.stringify({ notAPayload: true }),
    );
    expect(JSON.parse(resp).error).toBeDefined();
  });
});

// ─── Suite 2: fetchFederationRoute client ───────────────────────────────────

describe('fetchFederationRoute', () => {
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
    const { fetchFederationRoute } = await import('../node/federation-registry');
    const result = await fetchFederationRoute('http://127.0.0.1:1', 'echo.lattice', { timeoutMs: 500 });
    expect(result).toBeNull();
  });

  it('fetches only the requested route', async () => {
    server.localAnnounce({
      version: 2,
      fqdn: 'echo.lattice',
      gatewayPubKeyB64: 'key=',
      gatewayEndpoints: ['wss://relay.example.com:8889'],
    });
    const { fetchFederationRoute } = await import('../node/federation-registry');
    const result = await fetchFederationRoute(`http://127.0.0.1:${port}`, 'echo.lattice');
    expect(result).not.toBeNull();
    expect(result!.payload.fqdn).toBe('echo.lattice');
  });

  it('verifies HMAC when overlaySecret provided', async () => {
    server.localAnnounce({
      version: 2,
      fqdn: 'echo.lattice',
      gatewayPubKeyB64: 'key=',
      gatewayEndpoints: ['wss://relay.example.com:8889'],
    });
    const { fetchFederationRoute } = await import('../node/federation-registry');

    // Correct secret — should pass
    const ok = await fetchFederationRoute(`http://127.0.0.1:${port}`, 'echo.lattice', { overlaySecret });
    expect(ok).not.toBeNull();

    // Wrong secret — should return null
    const bad = await fetchFederationRoute(`http://127.0.0.1:${port}`, 'echo.lattice', {
      overlaySecret: crypto.randomBytes(32).toString('base64'),
    });
    expect(bad).toBeNull();
  });

  it('does not return other routes while fetching one signed route', async () => {
    server.localAnnounce({
      version: 2,
      fqdn: 'echo.lattice',
      gatewayPubKeyB64: overlayPubkey(),
      gatewayEndpoints: ['wss://relay.example.com:8889'],
    });
    server.localAnnounce({
      version: 2,
      fqdn: 'other.lattice',
      gatewayPubKeyB64: overlayPubkey(),
      gatewayEndpoints: ['wss://other.example.com:8889'],
    });
    const { fetchFederationRoute } = await import('../node/federation-registry');
    const route = await fetchFederationRoute(`http://127.0.0.1:${port}`, 'echo.lattice', { overlaySecret });
    expect(route?.payload.fqdn).toBe('echo.lattice');
    const rejected = await fetchFederationRoute(`http://127.0.0.1:${port}`, 'echo.lattice', {
      overlaySecret: crypto.randomBytes(32).toString('base64'),
    });
    expect(rejected).toBeNull();
  });

  it('drops oversized named-route replies rather than retaining an unbounded response', async () => {
    const oversized = http.createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': 65_537 });
      res.end('x'.repeat(65_537));
    });
    await new Promise<void>((resolve, reject) => oversized.listen(0, '127.0.0.1', resolve).once('error', reject));
    const address = oversized.address();
    if (!address || typeof address === 'string') throw new Error('Expected TCP address');
    const { fetchFederationRoute } = await import('../node/federation-registry');
    await expect(fetchFederationRoute(`http://127.0.0.1:${address.port}`, 'echo.lattice')).resolves.toBeNull();
    await new Promise<void>(resolve => oversized.close(() => resolve()));
  });
});

// ─── Suite 3: LpGatewayResolver federation step ──────────────────────────────

describe('LpGatewayResolver — federation resolution', () => {
  let fedServer: import('../node/federation-registry').FederationRegistryServer;
  let fedPort: number;
  let caOverlaySecret: string;

  beforeEach(async () => {
    // Use the CA overlaySecret so lp-resolver HMAC verification matches the server
    const { overlaySecret } = await freshLatticeHome();
    caOverlaySecret = overlaySecret;
    fedPort = await freePort();
    vi.resetModules();
    const { FederationRegistryServer } = await import('../node/federation-registry');
    fedServer = new FederationRegistryServer('127.0.0.1', fedPort, caOverlaySecret);
    fedServer.start();
    await sleep(100);
  });

  afterEach(() => fedServer.stop());

  it('resolves lp:// address from federation when no chain/routing-cache', async () => {
    const pubkey = overlayPubkey();
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
      overlayProtocol: 'onion-v1',
    } as any;
    const resolver = new LpGatewayResolver(cfg, null);
    await expect(resolver.resolveDestination('lp://notfound.lattice')).rejects.toBeInstanceOf(
      LpRoutingNotFoundError,
    );
  });

  it('negative-caches a federation miss instead of repeating registry discovery', async () => {
    vi.resetModules();
    const federation = await import('../node/federation-registry');
    const fetchRoute = vi.spyOn(federation, 'fetchFederationRoute').mockResolvedValue(null);
    const { LpGatewayResolver, LpRoutingNotFoundError } = await import('../node/lp-resolver');
    const resolver = new LpGatewayResolver({
      registry: { federationUrls: [`http://127.0.0.1:${fedPort}`] },
      distributedMesh: false,
    } as any, null);

    await expect(resolver.resolveDestination('lp://negative-cache.lattice')).rejects.toBeInstanceOf(
      LpRoutingNotFoundError,
    );
    await expect(resolver.resolveDestination('lp://negative-cache.lattice')).rejects.toBeInstanceOf(
      LpRoutingNotFoundError,
    );
    expect(fetchRoute).toHaveBeenCalledTimes(1);
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

  it('posts an announcement and it appears in GET /v1/routes/<fqdn>', async () => {
    const { postFederationAnnounce } = await import('../node/federation-registry');
    const pubkey = overlayPubkey();
    const ok = await postFederationAnnounce(
      `http://127.0.0.1:${port}`,
      {
        version: 2,
        fqdn: 'clipma.lattice',
        gatewayPubKeyB64: pubkey,
        gatewayEndpoints: ['wss://5.5.5.5:8889'],
      },
      { ttlSeconds: 90, announcerPubKey: pubkey, overlaySecret: 'secret' },
    );
    expect(ok).toBe(true);

    const route = JSON.parse(await httpGet(`http://127.0.0.1:${port}/v1/routes/clipma.lattice`));
    expect(route.route.payload.gatewayEndpoints).toContain('wss://5.5.5.5:8889');
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
        overlayProtocol: 'onion-v1',
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

  it('rejects global-sized relay or registry membership in a single cell config', async () => {
    const { home } = await freshLatticeHome();
    const yaml = await import('js-yaml');
    fs.writeFileSync(path.join(home, 'node.yaml'), yaml.dump({
      upstreamRelays: Array.from({ length: 17 }, (_, i) => `wss://relay-${i}.example.com:8888`),
      registry: { federationUrls: Array.from({ length: 65 }, (_, i) => `https://registry-${i}.example.com:9000`) },
    }));
    vi.resetModules();
    const { loadNodeConfig: lnc } = await import('../node/node-config');
    expect(() => lnc()).toThrow(/at most/i);
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
