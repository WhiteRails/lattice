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
 *   - Server signs its GET /v1/routes response with HMAC(overlaySecret)
 *   - Clients verify server HMAC before trusting routes (optional: requires shared CA secret)
 *   - TTL-based expiry: stale routes auto-removed; gateway must re-announce periodically
 */
import * as http from 'http';
import * as https from 'https';
import * as crypto from 'crypto';
import chalk from 'chalk';
import type { RoutingPayload } from './routing-cache';
import { normalizeRoutingPayload } from './routing-cache';
import { stableStringify } from './message';
import { readHttpsTlsCredentials } from './ws-stack';
import type { LatticeNodeYaml } from './node-config';

export const FEDERATION_DEFAULT_PORT = 9000;
export const FEDERATION_DEFAULT_TTL_SECONDS = 300;
export const FEDERATION_ANNOUNCE_PATH = '/v1/announce';
export const FEDERATION_ROUTES_PATH = '/v1/routes';
export const FEDERATION_HEALTH_PATH = '/v1/health';

/** One announced route in the federation registry. */
export interface FederationEntry {
  payload: RoutingPayload;
  announcedAt: string;       // ISO8601
  expiresAt: string;         // ISO8601
  announcerPubKey?: string;  // X25519 pubkey of announcing node (informational)
}

/** Body of GET /v1/routes */
export interface FederationRoutesResponse {
  version: 1;
  generatedAt: string;
  routes: Record<string, FederationEntry>;  // keyed by fqdn
  /** HMAC-SHA256(overlaySecret, stableStringify({version,generatedAt,routes})) */
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

// ─── Server ─────────────────────────────────────────────────────────────────

export class FederationRegistryServer {
  private routes: Map<string, FederationEntry> = new Map();
  private server: http.Server | https.Server;
  private sweepInterval: ReturnType<typeof setInterval> | null = null;

  constructor(
    private readonly bindHost: string,
    private readonly bindPort: number,
    private readonly overlaySecret: string,
    private readonly tls?: LatticeNodeYaml['tls'],
  ) {
    const handler = (req: http.IncomingMessage, res: http.ServerResponse) =>
      void this.handleRequest(req, res);
    const creds = readHttpsTlsCredentials(tls);
    this.server = creds
      ? https.createServer(creds, handler)
      : http.createServer(handler);
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
    this.upsertEntry(payload, ttlSeconds);
  }

  getRoutes(): Map<string, FederationEntry> {
    return this.routes;
  }

  private sweep(): void {
    const now = Date.now();
    for (const [fqdn, entry] of this.routes) {
      if (new Date(entry.expiresAt).getTime() < now) {
        this.routes.delete(fqdn);
        console.log(chalk.cyan('[Federation]') + ` Expired route: ${fqdn}`);
      }
    }
  }

  private upsertEntry(payload: RoutingPayload, ttlSeconds: number, announcerPubKey?: string): void {
    const normalized = normalizeRoutingPayload(payload);
    const now = new Date();
    const expiresAt = new Date(now.getTime() + ttlSeconds * 1000);
    // Only include optional fields if defined — avoids stableStringify/JSON.stringify mismatch
    const entry: FederationEntry = {
      payload: normalized,
      announcedAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
    };
    if (announcerPubKey) entry.announcerPubKey = announcerPubKey;
    this.routes.set(normalized.fqdn, entry);
    console.log(
      chalk.cyan('[Federation]') +
        ` Announced: ${normalized.fqdn} → [${normalized.gatewayEndpoints.join(', ')}] TTL=${ttlSeconds}s`,
    );
  }

  private buildRoutesResponse(): FederationRoutesResponse {
    const now = new Date().toISOString();
    const routes: Record<string, FederationEntry> = {};
    const nowMs = Date.now();
    for (const [fqdn, entry] of this.routes) {
      if (new Date(entry.expiresAt).getTime() > nowMs) {
        routes[fqdn] = entry;
      }
    }
    const body: Omit<FederationRoutesResponse, 'serverSig'> = { version: 1, generatedAt: now, routes };
    const sig = crypto
      .createHmac('sha256', Buffer.from(this.overlaySecret, 'utf8'))
      .update(stableStringify(body), 'utf8')
      .digest('hex');
    return { ...body, serverSig: sig };
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
      res.end(JSON.stringify({ ok: true, routes: this.routes.size }));
      return;
    }

    if (req.method === 'GET' && url === FEDERATION_ROUTES_PATH) {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify(this.buildRoutesResponse(), null, 2));
      return;
    }

    if (req.method === 'POST' && url === FEDERATION_ANNOUNCE_PATH) {
      const body = await readBody(req);
      let announce: AnnounceRequest;
      try {
        announce = JSON.parse(body) as AnnounceRequest;
        if (!announce.payload?.fqdn || !Array.isArray(announce.payload.gatewayEndpoints)) {
          throw new Error('Missing required payload fields');
        }
      } catch (e: any) {
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: `Invalid announce body: ${e?.message}` }));
        return;
      }

      // Verify HMAC authentication on announce requests
      const hmacBody: Record<string, unknown> = { payload: announce.payload };
      if (announce.ttlSeconds !== undefined) hmacBody.ttlSeconds = announce.ttlSeconds;
      if (announce.announcerPubKey !== undefined) hmacBody.announcerPubKey = announce.announcerPubKey;
      const expectedHmac = crypto
        .createHmac('sha256', Buffer.from(this.overlaySecret, 'utf8'))
        .update(stableStringify(hmacBody), 'utf8')
        .digest('hex');
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
      this.upsertEntry(announce.payload, ttl, announce.announcerPubKey);
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ ok: true, fqdn: announce.payload.fqdn, ttlSeconds: ttl }));
      return;
    }

    res.writeHead(404, { 'content-type': 'application/json' });
    res.end(JSON.stringify({ error: 'Not found' }));
  }
}

// ─── Client ─────────────────────────────────────────────────────────────────

/** Fetches and optionally verifies a federation registry response. */
export async function fetchFederationRoutes(
  registryUrl: string,
  opts: { overlaySecret?: string; timeoutMs?: number } = {},
): Promise<FederationRoutesResponse | null> {
  const url = `${registryUrl.replace(/\/$/, '')}${FEDERATION_ROUTES_PATH}`;
  try {
    const raw = await httpGet(url, opts.timeoutMs ?? 5000);
    const parsed = JSON.parse(raw) as FederationRoutesResponse;
    if (parsed.version !== 1 || !parsed.routes) return null;

    // Mandatory HMAC verification when we share the overlay secret
    if (opts.overlaySecret) {
      if (!parsed.serverSig) {
        console.warn(chalk.yellow('[Federation]') + ` No serverSig from ${registryUrl} — ignoring unsigned response`);
        return null;
      }
      const { serverSig, ...body } = parsed;
      const expected = crypto
        .createHmac('sha256', Buffer.from(opts.overlaySecret, 'utf8'))
        .update(stableStringify(body), 'utf8')
        .digest('hex');
      if (!crypto.timingSafeEqual(Buffer.from(serverSig, 'hex'), Buffer.from(expected, 'hex'))) {
        console.warn(chalk.yellow('[Federation]') + ` HMAC mismatch from ${registryUrl} — ignoring`);
        return null;
      }
    }
    return parsed;
  } catch (e: any) {
    console.warn(chalk.yellow('[Federation]') + ` Failed to fetch ${url}: ${e?.message}`);
    return null;
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
      const chunks: Buffer[] = [];
      res.on('data', (d: Buffer) => chunks.push(d));
      res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
      res.on('error', reject);
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
        const chunks: Buffer[] = [];
        res.on('data', (d: Buffer) => chunks.push(d));
        res.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
        res.on('error', reject);
      },
    );
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    req.on('error', reject);
    req.write(body);
    req.end();
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
