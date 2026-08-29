/**
 * Federation Registry — distributed lp:// routing table shared across Lattice nodes.
 *
 * Server: HTTP endpoint that accepts signed service announcements and serves routes.
 * Client: Polls remote federation servers to resolve lp:// addresses.
 *
 * Flow:
 *   Gateway starts → announces lp://echo.lattice + WSS endpoint to federation server
 *   Relay resolves lp://echo.lattice → polls federation → gets endpoint → routes traffic
 *
 * Security model:
 *   - Announcements carry the gateway's X25519 public key (base64 SPKI)
 *   - Server signs each GET /v1/routes/<fqdn> response with HMAC(overlaySecret)
 *   - Clients verify server HMAC before trusting routes (optional: requires shared CA secret)
 *   - TTL-based expiry: stale routes auto-removed; gateway must re-announce periodically
 */
import * as http from 'http';
import * as https from 'https';
import * as crypto from 'crypto';
import { z } from 'zod';
import chalk from 'chalk';
import type { RoutingPayload } from './routing-cache';
import { normalizeRoutingPayload } from './routing-cache';
import { stableStringify } from './message';
import { applyInboundHttpNetworkLimits, readHttpsTlsCredentials } from './ws-stack';
import { inboundNetworkLimitsFromEnv } from './network-limits';
import type { LatticeNodeYaml } from './node-config';
import { LATTICE_HPKE_SUITE } from './hpke-envelope';

export const FEDERATION_DEFAULT_PORT = 9000;
export const FEDERATION_DEFAULT_TTL_SECONDS = 300;
export const FEDERATION_ANNOUNCE_PATH = '/v1/announce';
export const FEDERATION_ROUTES_PATH = '/v1/routes';
export const DEFAULT_FEDERATION_MAX_ROUTES = 100_000;
const MIN_FEDERATION_MAX_ROUTES = 1_000;
const HARD_MAX_FEDERATION_MAX_ROUTES = 5_000_000;
const MAX_FEDERATION_RESPONSE_BYTES = 65_536;

export interface FederationRegistryOptions {
  /** Maximum live names held by this registry shard. Existing names may renew. */
  maxRoutes?: number;
}
export const FEDERATION_ROUTE_PREFIX = `${FEDERATION_ROUTES_PATH}/`;
export const FEDERATION_HEALTH_PATH = '/v1/health';

/** One announced route in the federation registry. */
export interface FederationEntry {
  payload: RoutingPayload;
  announcedAt: string;       // ISO8601
  expiresAt: string;         // ISO8601
  announcerPubKey?: string;  // X25519 pubkey of announcing node (informational)
}

interface ExpiringRoute {
  fqdn: string;
  expiresAtMs: number;
}

/** Compact response for one name. Public discovery never dumps a route table. */
export interface FederationRouteResponse {
  version: 1;
  generatedAt: string;
  fqdn: string;
  route: FederationEntry;
  /** HMAC-SHA256(overlaySecret, stableStringify({version,generatedAt,fqdn,route})) */
  serverSig?: string;
}

/** Body of POST /v1/announce */
export interface AnnounceRequest {
  payload: RoutingPayload;
  ttlSeconds?: number;
  announcerPubKey?: string;
  /** HMAC-SHA256(overlaySecret, stableStringify({payload, ttlSeconds, announcerPubKey})) */
  announceHmac?: string;
}

const RoutingPayloadV2Schema = z.object({
  version: z.literal(2),
  fqdn: z.string().min(3).max(253).regex(/^(?:[a-z0-9-]+\.)+(?:lattice|id)$/),
  gatewayNodeLabel: z.string().regex(/^[a-z0-9._-]{1,64}$/).optional(),
  gatewayPubKeyB64: z.string().regex(/^[A-Za-z0-9+/]{59}=$/),
  gatewayEndpoints: z.array(z.string().url().max(2_048)).min(1).max(16),
}).strict();

const RendezvousDescriptorSchema = z.object({
  nodeLabel: z.string().regex(/^[a-z0-9._-]{1,64}$/),
  endpoint: z.string().url().max(2_048),
  token: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  expiresAt: z.string().datetime({ offset: true }),
}).strict();

const RoutingPayloadV3Schema = z.object({
  version: z.literal(3),
  fqdn: z.string().min(3).max(253).regex(/^(?:[a-z0-9-]+\.)+(?:lattice|id)$/),
  gatewayNodeLabel: z.string().regex(/^[a-z0-9._-]{1,64}$/),
  gatewayPubKeyB64: z.string().regex(/^[A-Za-z0-9+/]{59}=$/),
  gatewayEndpoints: z.array(z.string().url().max(2_048)).max(16),
  gatewayEncryptionKeyId: z.string().regex(/^[a-f0-9]{64}$/),
  gatewayEncryptionPubKeyB64Url: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
  hpkeSuite: z.literal(LATTICE_HPKE_SUITE),
  delivery: z.discriminatedUnion('mode', [
    z.object({ mode: z.literal('public') }).strict(),
    z.object({ mode: z.literal('hidden'), rendezvous: z.array(RendezvousDescriptorSchema).min(1).max(16) }).strict(),
  ]),
}).strict().superRefine((value, ctx) => {
  if (value.delivery.mode === 'public' && value.gatewayEndpoints.length < 1) {
    ctx.addIssue({ code: z.ZodIssueCode.custom, path: ['gatewayEndpoints'], message: 'Public v3 routes require a Gateway endpoint' });
  }
});

const RoutingPayloadSchema = z.union([RoutingPayloadV2Schema, RoutingPayloadV3Schema]);

const AnnounceSchema = z.object({
  payload: RoutingPayloadSchema,
  ttlSeconds: z.number().int().min(1).max(86_400).optional(),
  announcerPubKey: z.string().regex(/^[A-Za-z0-9+/]{59}=$/).optional(),
  announceHmac: z.string().regex(/^[a-f0-9]{64}$/).optional(),
}).strict();

function federationMaxRoutesFromEnv(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.LATTICE_FEDERATION_MAX_ROUTES;
  if (raw === undefined || raw.trim() === '') return DEFAULT_FEDERATION_MAX_ROUTES;
  if (!/^[0-9]+$/.test(raw.trim())) {
    throw new Error('LATTICE_FEDERATION_MAX_ROUTES must be an integer');
  }
  return validMaxRoutes(Number(raw), MIN_FEDERATION_MAX_ROUTES);
}

function validMaxRoutes(value: number, minimum = 1): number {
  if (!Number.isSafeInteger(value) || value < minimum || value > HARD_MAX_FEDERATION_MAX_ROUTES) {
    throw new Error(
      `Federation maxRoutes must be between ${minimum} and ${HARD_MAX_FEDERATION_MAX_ROUTES}`,
    );
  }
  return value;
}

// ─── Server ─────────────────────────────────────────────────────────────────

export class FederationRegistryServer {
  private readonly routes = new Map<string, FederationEntry>();
  /** Indexed min-heap: one expiry row per live route, even after renewals. */
  private readonly expiryHeap: ExpiringRoute[] = [];
  private readonly expiryIndex = new Map<string, number>();
  private server: http.Server | https.Server;
  private sweepInterval: ReturnType<typeof setInterval> | null = null;
  private readonly maxRoutes: number;

  constructor(
    private readonly bindHost: string,
    private readonly bindPort: number,
    private readonly overlaySecret: string,
    private readonly tls?: LatticeNodeYaml['tls'],
    options: FederationRegistryOptions = {},
  ) {
    this.maxRoutes = validMaxRoutes(options.maxRoutes ?? federationMaxRoutesFromEnv());
    const handler = (req: http.IncomingMessage, res: http.ServerResponse) => {
      void this.handleRequest(req, res).catch((e: unknown) => {
        if (!res.headersSent) {
          res.writeHead(400, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: 'Invalid federation request' }));
        }
        console.warn(chalk.yellow('[Federation]') + ` Rejected request: ${String(e)}`);
      });
    };
    const creds = readHttpsTlsCredentials(tls);
    this.server = creds
      ? https.createServer(creds, handler)
      : http.createServer(handler);
    // A registry is a public control-plane shard, so it needs the same bounded
    // socket budget as dataplane roles. Route-entry limits alone do not stop
    // slow headers or idle keep-alives from consuming all descriptors.
    applyInboundHttpNetworkLimits(this.server, inboundNetworkLimitsFromEnv());
  }

  start(): void {
    this.server.listen(this.bindPort, this.bindHost, () => {
      const scheme = this.tls?.certFile ? 'https' : 'http';
      console.log(
        chalk.cyan('[Federation]') +
          ` Registry serving on ${scheme}://${this.bindHost}:${this.bindPort}`,
      );
    });
    this.server.on('error', (e) =>
      console.error(chalk.red('[Federation] server error'), e.message),
    );
    // Sweep expired routes every 60 s
    this.sweepInterval = setInterval(() => this.sweep(), 60_000);
  }

  stop(): void {
    if (this.sweepInterval) clearInterval(this.sweepInterval);
    this.server.close();
  }

  /** Directly register a local route (e.g. when this node runs a gateway too). */
  localAnnounce(payload: RoutingPayload, ttlSeconds = FEDERATION_DEFAULT_TTL_SECONDS): void {
    if (!this.upsertEntry(payload, ttlSeconds)) {
      throw new Error(`Federation registry capacity reached (${this.maxRoutes} routes)`);
    }
  }

  getRoutes(): Map<string, FederationEntry> {
    return this.routes;
  }

  snapshot(): { routes: number; expiryEntries: number; maxRoutes: number } {
    return { routes: this.routes.size, expiryEntries: this.expiryHeap.length, maxRoutes: this.maxRoutes };
  }

  private sweep(): void {
    const now = Date.now();
    let expired = 0;
    while (this.expiryHeap[0]?.expiresAtMs <= now) {
      const entry = this.removeExpiryAt(0)!;
      this.routes.delete(entry.fqdn);
      expired++;
    }
    if (expired) console.log(chalk.cyan('[Federation]') + ` Expired ${expired} route(s)`);
  }

  private upsertEntry(payload: RoutingPayload, ttlSeconds: number, announcerPubKey?: string): boolean {
    const normalized = normalizeRoutingPayload(payload);
    // Sweep before rejecting a new route so expired names never consume a
    // shard slot until the next periodic sweep.
    if (!this.routes.has(normalized.fqdn)) {
      this.sweep();
      if (this.routes.size >= this.maxRoutes) return false;
    }
    const now = new Date();
    const expiresAtMs = now.getTime() + ttlSeconds * 1000;
    const expiresAt = new Date(expiresAtMs);
    // Only include optional fields if defined — avoids stableStringify/JSON.stringify mismatch
    const entry: FederationEntry = {
      payload: normalized,
      announcedAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
    };
    if (announcerPubKey) entry.announcerPubKey = announcerPubKey;
    this.routes.set(normalized.fqdn, entry);
    this.setExpiry(normalized.fqdn, expiresAtMs);
    console.log(
      chalk.cyan('[Federation]') +
        ` Announced: ${normalized.fqdn} → [${normalized.gatewayEndpoints.join(', ')}] TTL=${ttlSeconds}s`,
    );
    return true;
  }

  private buildRouteResponse(fqdn: string, route: FederationEntry): FederationRouteResponse {
    const body: Omit<FederationRouteResponse, 'serverSig'> = {
      version: 1,
      generatedAt: new Date().toISOString(),
      fqdn,
      route,
    };
    const serverSig = crypto
      .createHmac('sha256', Buffer.from(this.overlaySecret, 'utf8'))
      .update(stableStringify(body), 'utf8')
      .digest('hex');
    return { ...body, serverSig };
  }

  private async handleRequest(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const url = req.url?.split('?')[0] ?? '/';

    // CORS restricted to localhost dev tooling only — never wildcard on announce
    const origin = req.headers['origin'];
    if (origin && /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    }
    if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

    if (req.method === 'GET' && url === FEDERATION_HEALTH_PATH) {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, routes: this.routes.size, maxRoutes: this.maxRoutes }));
      return;
    }

    if (req.method === 'GET' && url === FEDERATION_ROUTES_PATH) {
      res.writeHead(410, { 'content-type': 'application/json' });
      res.end(JSON.stringify({
        error: 'Global route listing is not available; request /v1/routes/<fqdn>',
      }));
      return;
    }

    if (req.method === 'GET' && url.startsWith(FEDERATION_ROUTE_PREFIX)) {
      let fqdn: string;
      try {
        fqdn = decodeURIComponent(url.slice(FEDERATION_ROUTE_PREFIX.length)).toLowerCase();
      } catch {
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid route name' }));
        return;
      }
      if (!/^(?:[a-z0-9-]+\.)+(?:lattice|id)$/.test(fqdn)) {
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid route name' }));
        return;
      }
      const entry = this.routes.get(fqdn);
      if (!entry || this.routeExpiry(fqdn) === undefined || this.routeExpiry(fqdn)! <= Date.now()) {
        this.removeRoute(fqdn);
        res.writeHead(404, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'Route not found' }));
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(this.buildRouteResponse(fqdn, entry)));
      return;
    }

    if (req.method === 'POST' && url === FEDERATION_ANNOUNCE_PATH) {
      let announce: AnnounceRequest;
      try {
        const body = await readBody(req);
        announce = AnnounceSchema.parse(JSON.parse(body));
      } catch {
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid announce body' }));
        return;
      }

      // Verify HMAC authentication on announce requests
      const hmacBody: Record<string, unknown> = { payload: announce.payload };
      if (announce.ttlSeconds !== undefined) hmacBody.ttlSeconds = announce.ttlSeconds;
      if (announce.announcerPubKey !== undefined) hmacBody.announcerPubKey = announce.announcerPubKey;
      let expectedHmac: string;
      try {
        expectedHmac = crypto
          .createHmac('sha256', Buffer.from(this.overlaySecret, 'utf8'))
          .update(stableStringify(hmacBody), 'utf8')
          .digest('hex');
      } catch {
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid announce payload' }));
        return;
      }
      const providedHmac = announce.announceHmac ?? '';
      let hmacOk = false;
      try {
        hmacOk = providedHmac.length > 0 &&
          crypto.timingSafeEqual(Buffer.from(providedHmac, 'hex'), Buffer.from(expectedHmac, 'hex'));
      } catch {
        hmacOk = false;
      }
      if (!hmacOk) {
        res.writeHead(401, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'Announce authentication failed' }));
        return;
      }

      const ttl = Math.max(30, Math.min(announce.ttlSeconds ?? FEDERATION_DEFAULT_TTL_SECONDS, 3600));
      if (!this.upsertEntry(announce.payload, ttl, announce.announcerPubKey)) {
        res.writeHead(503, { 'content-type': 'application/json', 'retry-after': '1' });
        res.end(JSON.stringify({ error: 'Federation shard at route capacity' }));
        return;
      }
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, fqdn: announce.payload.fqdn, ttlSeconds: ttl }));
      return;
    }

    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not found' }));
  }

  private routeExpiry(fqdn: string): number | undefined {
    const index = this.expiryIndex.get(fqdn);
    return index === undefined ? undefined : this.expiryHeap[index]?.expiresAtMs;
  }

  private removeRoute(fqdn: string): void {
    this.routes.delete(fqdn);
    const index = this.expiryIndex.get(fqdn);
    if (index !== undefined) this.removeExpiryAt(index);
  }

  private setExpiry(fqdn: string, expiresAtMs: number): void {
    const index = this.expiryIndex.get(fqdn);
    if (index === undefined) {
      this.expiryHeap.push({ fqdn, expiresAtMs });
      this.expiryIndex.set(fqdn, this.expiryHeap.length - 1);
      this.siftUp(this.expiryHeap.length - 1);
      return;
    }
    const previous = this.expiryHeap[index]!.expiresAtMs;
    this.expiryHeap[index] = { fqdn, expiresAtMs };
    if (expiresAtMs < previous) this.siftUp(index);
    else this.siftDown(index);
  }

  private removeExpiryAt(index: number): ExpiringRoute | undefined {
    const removed = this.expiryHeap[index];
    const last = this.expiryHeap.pop();
    if (!removed || !last) return undefined;
    this.expiryIndex.delete(removed.fqdn);
    if (index === this.expiryHeap.length) return removed;
    this.expiryHeap[index] = last;
    this.expiryIndex.set(last.fqdn, index);
    const parent = Math.floor((index - 1) / 2);
    if (index > 0 && this.expiryHeap[index]!.expiresAtMs < this.expiryHeap[parent]!.expiresAtMs) this.siftUp(index);
    else this.siftDown(index);
    return removed;
  }

  private siftUp(index: number): void {
    let child = index;
    while (child > 0) {
      const parent = Math.floor((child - 1) / 2);
      if (this.expiryHeap[parent]!.expiresAtMs <= this.expiryHeap[child]!.expiresAtMs) break;
      this.swapExpiry(parent, child);
      child = parent;
    }
  }

  private siftDown(index: number): void {
    let parent = index;
    while (true) {
      const left = parent * 2 + 1;
      if (left >= this.expiryHeap.length) return;
      const right = left + 1;
      const child = right < this.expiryHeap.length &&
        this.expiryHeap[right]!.expiresAtMs < this.expiryHeap[left]!.expiresAtMs ? right : left;
      if (this.expiryHeap[parent]!.expiresAtMs <= this.expiryHeap[child]!.expiresAtMs) return;
      this.swapExpiry(parent, child);
      parent = child;
    }
  }

  private swapExpiry(left: number, right: number): void {
    const a = this.expiryHeap[left]!;
    const b = this.expiryHeap[right]!;
    this.expiryHeap[left] = b;
    this.expiryHeap[right] = a;
    this.expiryIndex.set(a.fqdn, right);
    this.expiryIndex.set(b.fqdn, left);
  }
}

// ─── Client ─────────────────────────────────────────────────────────────────

/** Resolves one name without transferring the federation's entire route table. */
export async function fetchFederationRoute(
  registryUrl: string,
  fqdn: string,
  opts: { overlaySecret?: string; timeoutMs?: number } = {},
): Promise<FederationEntry | null> {
  const canonicalFqdn = fqdn.trim().toLowerCase();
  if (!/^(?:[a-z0-9-]+\.)+(?:lattice|id)$/.test(canonicalFqdn)) return null;
  const url = `${registryUrl.replace(/\/$/, '')}${FEDERATION_ROUTE_PREFIX}${encodeURIComponent(canonicalFqdn)}`;
  try {
    const raw = await httpGet(url, opts.timeoutMs ?? 5000);
    const parsed = JSON.parse(raw) as FederationRouteResponse;
    if (parsed.version !== 1 || parsed.fqdn !== canonicalFqdn || !parsed.route) return null;
    if (!verifyFederationSignature(parsed, opts.overlaySecret, registryUrl)) return null;
    return parsed.route;
  } catch (e: any) {
    console.warn(chalk.yellow('[Federation]') + ` Failed to fetch ${url}: ${e?.message}`);
    return null;
  }
}

function verifyFederationSignature(
  response: { serverSig?: string },
  overlaySecret: string | undefined,
  registryUrl: string,
): boolean {
  if (!overlaySecret) return true;
  if (!response.serverSig) {
    console.warn(chalk.yellow('[Federation]') + ` No serverSig from ${registryUrl} — ignoring unsigned response`);
    return false;
  }
  try {
    const { serverSig, ...body } = response;
    const expected = crypto
      .createHmac('sha256', Buffer.from(overlaySecret, 'utf8'))
      .update(stableStringify(body), 'utf8')
      .digest('hex');
    const got = Buffer.from(serverSig, 'hex');
    const exp = Buffer.from(expected, 'hex');
    if (got.length !== exp.length || !crypto.timingSafeEqual(got, exp)) {
      console.warn(chalk.yellow('[Federation]') + ` HMAC mismatch from ${registryUrl} — ignoring`);
      return false;
    }
    return true;
  } catch {
    console.warn(chalk.yellow('[Federation]') + ` Invalid signature from ${registryUrl} — ignoring`);
    return false;
  }
}

/** POST an announcement to a remote federation registry. */
export async function postFederationAnnounce(
  registryUrl: string,
  payload: RoutingPayload,
  opts: { ttlSeconds?: number; announcerPubKey?: string; timeoutMs?: number; overlaySecret?: string } = {},
): Promise<boolean> {
  const url = `${registryUrl.replace(/\/$/, '')}${FEDERATION_ANNOUNCE_PATH}`;
  const normalizedPayload = normalizeRoutingPayload(payload);
  const ttlSeconds = opts.ttlSeconds ?? FEDERATION_DEFAULT_TTL_SECONDS;
  const body: AnnounceRequest = { payload: normalizedPayload, ttlSeconds };
  if (opts.announcerPubKey) body.announcerPubKey = opts.announcerPubKey;

  // Compute announce HMAC when overlaySecret is available
  if (opts.overlaySecret) {
    const hmacBody: Record<string, unknown> = { payload: normalizedPayload, ttlSeconds };
    if (opts.announcerPubKey) hmacBody.announcerPubKey = opts.announcerPubKey;
    body.announceHmac = crypto
      .createHmac('sha256', Buffer.from(opts.overlaySecret, 'utf8'))
      .update(stableStringify(hmacBody), 'utf8')
      .digest('hex');
  }
  try {
    await httpPost(url, JSON.stringify(body), opts.timeoutMs ?? 5000);
    return true;
  } catch (e: any) {
    console.warn(chalk.yellow('[Federation]') + ` Announce to ${url} failed: ${e?.message}`);
    return false;
  }
}

// ─── HTTP helpers ────────────────────────────────────────────────────────────

function httpGet(url: string, timeoutMs: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith('https') ? https : http;
    const req = lib.get(url, { timeout: timeoutMs }, (res) => {
      void readLimitedResponse(res, MAX_FEDERATION_RESPONSE_BYTES).then(resolve, reject);
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    req.on('error', reject);
  });
}

function httpPost(url: string, body: string, timeoutMs: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const lib = url.startsWith('https') ? https : http;
    const parsed = new URL(url);
    const req = lib.request(
      {
        hostname: parsed.hostname,
        port: parsed.port || (url.startsWith('https') ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method: 'POST',
        headers: { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) },
        timeout: timeoutMs,
      },
      (res) => {
        void readLimitedResponse(res, MAX_FEDERATION_RESPONSE_BYTES).then(resolve, reject);
      },
    );
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

/** A registry client only accepts one compact, named route response. */
function readLimitedResponse(res: http.IncomingMessage, maxBytes: number): Promise<string> {
  return new Promise((resolve, reject) => {
    const declared = Number(res.headers['content-length'] ?? 0);
    if (Number.isFinite(declared) && declared > maxBytes) {
      res.destroy();
      reject(new Error('federation response too large'));
      return;
    }
    const chunks: Buffer[] = [];
    let total = 0;
    let settled = false;
    const fail = (error: Error) => {
      if (settled) return;
      settled = true;
      reject(error);
    };
    res.on('data', (chunk: Buffer) => {
      total += chunk.length;
      if (total > maxBytes) {
        res.destroy();
        fail(new Error('federation response too large'));
        return;
      }
      chunks.push(chunk);
    });
    res.on('end', () => {
      if (settled) return;
      settled = true;
      resolve(Buffer.concat(chunks).toString('utf8'));
    });
    res.on('error', error => fail(error instanceof Error ? error : new Error(String(error))));
  });
}

const MAX_ANNOUNCE_BODY_BYTES = 65_536; // 64 KiB

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let totalBytes = 0;
    req.on('data', (d: Buffer) => {
      totalBytes += d.length;
      if (totalBytes > MAX_ANNOUNCE_BODY_BYTES) {
        req.destroy(new Error('request body too large'));
        reject(new Error('request body too large'));
        return;
      }
      chunks.push(d);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}
