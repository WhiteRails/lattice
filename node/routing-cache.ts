/**
 * Signed local cache: lp:// fqdn commitments + optional bootstrap node pubkeys for distributed mesh.
 */
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { ethers } from 'ethers';
import { stableStringify } from './message';
import { loadCA } from './state';
import { DEFAULT_ROUTING_CACHE_PATH, LatticeNodeYaml } from './node-config';
import { LATTICE_HPKE_SUITE } from './hpke-envelope';

export const ROUTING_PAYLOAD_VERSION = 3 as const;
export const DEFAULT_ROUTING_CACHE_MAX_ROUTES = 100_000;
export const DEFAULT_ROUTING_CACHE_MAX_FILE_BYTES = 64 * 1024 * 1024;
/** A data-plane Relay scores every endpoint; keep that work bounded per route. */
export const MAX_GATEWAY_ENDPOINTS_PER_ROUTE = 16;
export const MAX_GATEWAY_ENDPOINT_BYTES = 2_048;
const MIN_ROUTING_CACHE_MAX_ROUTES = 1_000;
const HARD_MAX_ROUTING_CACHE_MAX_ROUTES = 5_000_000;
const MIN_ROUTING_CACHE_MAX_FILE_BYTES = 1 * 1024 * 1024;
const HARD_MAX_ROUTING_CACHE_MAX_FILE_BYTES = 512 * 1024 * 1024;
const ROUTING_CACHE_REVALIDATE_MS = 1_000;
const MAX_RESIDENT_ROUTING_FILES = 4;
export type RoutingPayloadVersion = 1 | 2 | typeof ROUTING_PAYLOAD_VERSION;

export interface RendezvousDescriptor {
  nodeLabel: string;
  endpoint: string;
  token: string;
  expiresAt: string;
}

/** Serialized into chain metadataHash hex (canonical JSON UTF-8, keccak256). */
export interface RoutingPayload {
  version: RoutingPayloadVersion;
  fqdn: string;
  gatewayNodeLabel?: string;
  gatewayPubKeyB64: string;
  gatewayEndpoints: string[];
  gatewayEncryptionKeyId?: string;
  gatewayEncryptionPubKeyB64Url?: string;
  hpkeSuite?: typeof LATTICE_HPKE_SUITE;
  delivery?:
    | { mode: 'public' }
    | { mode: 'hidden'; rendezvous: RendezvousDescriptor[] };
}

export interface RoutingBundle {
  version: 1;
  exportedAt: string;
  route: RoutingPayload;
  metadataHash: string;
}

/** File at DEFAULT_ROUTING_CACHE_PATH (or configured path). */
export interface RoutingCacheFile {
  version: number;
  /** fqdn lowercase e.g. echo.lattice */
  routes: Record<string, { payload: RoutingPayload; updatedAt: string }>;
  /** operator bootstrap: lattice node label → overlay SPKI pubkey (same encoding as on-chain latticeNodes bytes). */
  latticeNodes: Record<
    string,
    {
      overlayPubKeyB64: string;
      /** Dedicated Ed25519 node identity (SPKI DER, base64). */
      identityPubKeyB64?: string;
      /** Dedicated raw X25519 ntor key (base64url). */
      onionPubKeyB64Url?: string;
      /** Governance-assigned operator identifier; distinct operators are required per circuit. */
      operatorId?: string;
      endpoint?: string;
      roleBitmask?: number;
      tlsFingerprintSha256?: string;
      updatedAt: string;
    }
  >;
  /** HMAC-SHA256(H(overlaySecret-utf8), canonical body) hex for local bootstrap rows. */
  hmacSig?: string;
}

export interface RoutingCacheLimits {
  /** Per-cell route budget; direct callers may use a lower number in tests. */
  maxRoutes?: number;
  /** Per-cell bootstrap-node budget; defaults to the route budget. */
  maxLatticeNodes?: number;
}

interface CachedRoutingFile {
  file: RoutingCacheFile;
  validSignature: boolean;
  checkedAtMs: number;
  mtimeMs: number;
  size: number;
}

const routingFileCache = new Map<string, CachedRoutingFile>();
const LATTICE_NODE_LABEL_RE = /^[a-z0-9._-]{1,64}$/;

export function routingCacheMaxRoutesFromEnv(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.LATTICE_ROUTING_CACHE_MAX_ROUTES;
  if (raw === undefined || raw.trim() === '') return DEFAULT_ROUTING_CACHE_MAX_ROUTES;
  if (!/^[0-9]+$/.test(raw.trim())) throw new Error('LATTICE_ROUTING_CACHE_MAX_ROUTES must be an integer');
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < MIN_ROUTING_CACHE_MAX_ROUTES || value > HARD_MAX_ROUTING_CACHE_MAX_ROUTES) {
    throw new Error(`LATTICE_ROUTING_CACHE_MAX_ROUTES must be between ${MIN_ROUTING_CACHE_MAX_ROUTES} and ${HARD_MAX_ROUTING_CACHE_MAX_ROUTES}`);
  }
  return value;
}

/** Maximum serialized route artifact retained or parsed by one cell. */
export function routingCacheMaxFileBytesFromEnv(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.LATTICE_ROUTING_CACHE_MAX_FILE_BYTES;
  if (raw === undefined || raw.trim() === '') return DEFAULT_ROUTING_CACHE_MAX_FILE_BYTES;
  if (!/^[0-9]+$/.test(raw.trim())) throw new Error('LATTICE_ROUTING_CACHE_MAX_FILE_BYTES must be an integer');
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < MIN_ROUTING_CACHE_MAX_FILE_BYTES || value > HARD_MAX_ROUTING_CACHE_MAX_FILE_BYTES) {
    throw new Error(
      `LATTICE_ROUTING_CACHE_MAX_FILE_BYTES must be between ${MIN_ROUTING_CACHE_MAX_FILE_BYTES} and ${HARD_MAX_ROUTING_CACHE_MAX_FILE_BYTES}`,
    );
  }
  return value;
}

/** Resident parsed routing artifacts are per-process LRU state, not a registry. */
export function routingFileCacheSnapshot(): { entries: number; maxEntries: number } {
  return { entries: routingFileCache.size, maxEntries: MAX_RESIDENT_ROUTING_FILES };
}

export function routingCommitmentHex(payload: RoutingPayload): string {
  return ethers.keccak256(ethers.toUtf8Bytes(stableStringify(normalizeRoutingPayload(payload)))).toLowerCase();
}

export function routingCacheDiskPath(cfg: LatticeNodeYaml | null): string {
  const fromCfg = cfg?.registry?.cacheFile?.trim();
  if (fromCfg) return path.isAbsolute(fromCfg) ? fromCfg : path.resolve(process.cwd(), fromCfg);
  return DEFAULT_ROUTING_CACHE_PATH;
}

export function fqdnFromLpAddress(lp: string): string {
  let s = lp.trim();
  if (s.startsWith('lp://')) s = s.slice(5);
  s = s.split('/')[0] ?? '';
  const lower = s.toLowerCase();
  if (!lower.endsWith('.lattice') && !lower.endsWith('.id')) {
    throw new Error(`Invalid Lattice service address (expected *.lattice or *.id): ${lp}`);
  }
  return lower;
}

export function lpFromFqdn(fqdn: string): string {
  const f = fqdn.trim().toLowerCase();
  const core = f.replace(/^lp:\/\//, '');
  return `lp://${core}`;
}

function canonicalBodyForSig(f: Omit<RoutingCacheFile, 'hmacSig'>): string {
  return stableStringify({ version: f.version, routes: f.routes, latticeNodes: f.latticeNodes });
}

/** CA overlaySecret stored as base64; hash to 32-byte HMAC key material. */
function routingHmacKey(secretRaw: string): Buffer {
  return crypto.createHash('sha256').update(secretRaw, 'utf8').digest();
}

export function routingHmac(secretRaw: string, bodyCanon: string): string {
  return crypto.createHmac('sha256', routingHmacKey(secretRaw)).update(bodyCanon, 'utf8').digest('hex');
}

export function normalizeRoutingPayload(payload: RoutingPayload): RoutingPayload {
  const rawEndpoints: unknown = payload.gatewayEndpoints;
  if (!Array.isArray(rawEndpoints) || rawEndpoints.length > MAX_GATEWAY_ENDPOINTS_PER_ROUTE) {
    throw new Error(`Routing payload must contain at most ${MAX_GATEWAY_ENDPOINTS_PER_ROUTE} gateway endpoints`);
  }
  const gatewayEndpoints: string[] = [];
  const seenEndpoints = new Set<string>();
  for (const rawEndpoint of rawEndpoints) {
    if (typeof rawEndpoint !== 'string') throw new Error('Routing gateway endpoint must be a string');
    const endpoint = rawEndpoint.trim();
    if (!endpoint) continue;
    if (Buffer.byteLength(endpoint, 'utf8') > MAX_GATEWAY_ENDPOINT_BYTES) {
      throw new Error(`Routing gateway endpoint exceeds ${MAX_GATEWAY_ENDPOINT_BYTES} bytes`);
    }
    // Validate syntax early. Relay later opens these as WebSockets, so a
    // non-websocket scheme is invalid rather than a costly retry candidate.
    let url: URL;
    try {
      url = new URL(endpoint);
    } catch {
      throw new Error('Routing gateway endpoint must be an absolute WebSocket URL');
    }
    if (url.protocol !== 'ws:' && url.protocol !== 'wss:') {
      throw new Error('Routing gateway endpoint must use ws or wss');
    }
    if (!seenEndpoints.has(endpoint)) {
      seenEndpoints.add(endpoint);
      gatewayEndpoints.push(endpoint);
    }
  }
  const normalized: RoutingPayload = {
    version: payload.version ?? ROUTING_PAYLOAD_VERSION,
    fqdn: payload.fqdn.toLowerCase(),
    gatewayPubKeyB64: payload.gatewayPubKeyB64.trim(),
    gatewayEndpoints,
  };
  if (payload.version === ROUTING_PAYLOAD_VERSION) {
    const encryptionKeyId = payload.gatewayEncryptionKeyId?.trim().toLowerCase();
    const encryptionPublicKey = payload.gatewayEncryptionPubKeyB64Url?.trim();
    if (encryptionKeyId !== undefined) {
      if (!/^[a-f0-9]{64}$/.test(encryptionKeyId)) throw new Error('Invalid Gateway encryption key id');
      normalized.gatewayEncryptionKeyId = encryptionKeyId;
    }
    if (encryptionPublicKey !== undefined) {
      if (!/^[A-Za-z0-9_-]{43}$/.test(encryptionPublicKey)) throw new Error('Invalid Gateway HPKE public key');
      normalized.gatewayEncryptionPubKeyB64Url = encryptionPublicKey;
    }
    if (payload.hpkeSuite !== undefined) {
      if (payload.hpkeSuite !== LATTICE_HPKE_SUITE) throw new Error('Unsupported Gateway HPKE suite');
      normalized.hpkeSuite = payload.hpkeSuite;
    }
    if (payload.delivery?.mode === 'public') {
      normalized.delivery = { mode: 'public' };
    } else if (payload.delivery?.mode === 'hidden') {
      if (!Array.isArray(payload.delivery.rendezvous) || payload.delivery.rendezvous.length < 1 || payload.delivery.rendezvous.length > 16) {
        throw new Error('Hidden routes require 1-16 rendezvous descriptors');
      }
      normalized.delivery = {
        mode: 'hidden',
        rendezvous: payload.delivery.rendezvous.map(normalizeRendezvousDescriptor),
      };
    }
  }
  const label = payload.gatewayNodeLabel?.trim();
  if (label) normalized.gatewayNodeLabel = label;
  return normalized;
}

export function assertEncryptedRoutingPayload(payload: RoutingPayload): asserts payload is RoutingPayload & Required<Pick<
  RoutingPayload,
  'gatewayEncryptionKeyId' | 'gatewayEncryptionPubKeyB64Url' | 'hpkeSuite' | 'delivery'
>> {
  if (payload.version !== ROUTING_PAYLOAD_VERSION ||
      !payload.gatewayEncryptionKeyId || !payload.gatewayEncryptionPubKeyB64Url ||
      payload.hpkeSuite !== LATTICE_HPKE_SUITE || !payload.delivery) {
    throw new Error('ROUTE_ENCRYPTION_REQUIRED: distributed mesh requires a complete v3 encrypted route');
  }
  if (payload.delivery.mode === 'public' && payload.gatewayEndpoints.length < 1) {
    throw new Error('ROUTE_ENCRYPTION_REQUIRED: public encrypted route has no Gateway endpoint');
  }
}

function normalizeRendezvousDescriptor(value: RendezvousDescriptor): RendezvousDescriptor {
  const nodeLabel = value.nodeLabel?.trim();
  if (!/^[a-z0-9._-]{1,64}$/.test(nodeLabel)) throw new Error('Invalid rendezvous node label');
  const endpoint = new URL(value.endpoint);
  if (endpoint.protocol !== 'wss:' && endpoint.protocol !== 'ws:') throw new Error('Rendezvous endpoint must use WebSocket');
  const token = value.token?.trim();
  if (!/^[A-Za-z0-9_-]{43}$/.test(token)) throw new Error('Invalid rendezvous token');
  const expiresAt = new Date(value.expiresAt);
  if (!Number.isFinite(expiresAt.getTime())) throw new Error('Invalid rendezvous expiry');
  return { nodeLabel, endpoint: endpoint.toString(), token, expiresAt: expiresAt.toISOString() };
}

export function readRoutingCacheFile(
  cfg: LatticeNodeYaml | null,
  opts: { requireLocalSig?: boolean } = {},
): RoutingCacheFile | null {
  const p = routingCacheDiskPath(cfg);
  const now = Date.now();
  const cached = routingFileCache.get(p);
  if (cached) touchRoutingFileCache(p, cached);
  // The contents are already authenticated. Do not put a synchronous stat(2)
  // on every data-plane route lookup; one cell-wide revalidation per interval
  // bounds propagation delay while preserving event-loop throughput.
  if (cached && now - cached.checkedAtMs < ROUTING_CACHE_REVALIDATE_MS) {
    return cachedRoutingFile(cached, p, opts);
  }
  let stat: fs.Stats;
  try {
    stat = fs.statSync(p);
  } catch {
    routingFileCache.delete(p);
    return null;
  }
  const maxFileBytes = routingCacheMaxFileBytesFromEnv();
  if (stat.size > maxFileBytes) {
    routingFileCache.delete(p);
    throw new Error(`Routing cache exceeds ${maxFileBytes} bytes: ${p}`);
  }
  if (cached && cached.mtimeMs === stat.mtimeMs && cached.size === stat.size) {
    cached.checkedAtMs = now;
    return cachedRoutingFile(cached, p, opts);
  }

  const raw = fs.readFileSync(p, 'utf8');
  const parsed = JSON.parse(raw) as RoutingCacheFile;
  assertRoutingCacheCardinality(parsed, routingCacheMaxRoutesFromEnv());
  let validSignature = false;
  if (!parsed.hmacSig || typeof parsed.hmacSig !== 'string') {
    validSignature = false;
  } else {
    const { hmacSig, ...rest } = parsed;
    const canon = canonicalBodyForSig(rest);
    const secret = loadCA().overlaySecret;
    const expected = routingHmac(secret, canon);
    const got = Buffer.from(hmacSig, 'hex');
    const expBuf = Buffer.from(expected, 'hex');
    validSignature = got.length === expBuf.length && crypto.timingSafeEqual(got, expBuf);
  }
  const next = { file: parsed, validSignature, checkedAtMs: now, mtimeMs: stat.mtimeMs, size: stat.size };
  touchRoutingFileCache(p, next);
  return cachedRoutingFile(next, p, opts);
}

function cachedRoutingFile(
  cached: CachedRoutingFile,
  filePath: string,
  opts: { requireLocalSig?: boolean },
): RoutingCacheFile {
  if (!cached.validSignature && opts.requireLocalSig !== false) {
    throw new Error(`Invalid routing cache (missing or invalid hmacSig): ${filePath}`);
  }
  return cached.file;
}

function writeAtomic(filePath: string, data: RoutingCacheFile): void {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const tmp = `${filePath}.tmp`;
  const serialized = JSON.stringify(data, null, 2);
  const bytes = Buffer.byteLength(serialized, 'utf8');
  const maxFileBytes = routingCacheMaxFileBytesFromEnv();
  if (bytes > maxFileBytes) {
    throw new Error(`Routing cache exceeds ${maxFileBytes} bytes; shard or expire inactive routes`);
  }
  fs.writeFileSync(tmp, serialized, { mode: 0o600 });
  fs.renameSync(tmp, filePath);
  fs.chmodSync(filePath, 0o600);
  const stat = fs.statSync(filePath);
  touchRoutingFileCache(filePath, {
    file: data,
    validSignature: true,
    checkedAtMs: Date.now(),
    mtimeMs: stat.mtimeMs,
    size: stat.size,
  });
}

function touchRoutingFileCache(filePath: string, value: CachedRoutingFile): void {
  routingFileCache.delete(filePath);
  while (routingFileCache.size >= MAX_RESIDENT_ROUTING_FILES) {
    const oldest = routingFileCache.keys().next().value as string | undefined;
    if (oldest === undefined) break;
    routingFileCache.delete(oldest);
  }
  routingFileCache.set(filePath, value);
}

function emptyRoutingBase(): Omit<RoutingCacheFile, 'hmacSig'> {
  return { version: 1, routes: {}, latticeNodes: {} };
}

function seal(base: Omit<RoutingCacheFile, 'hmacSig'>): RoutingCacheFile {
  const canon = canonicalBodyForSig(base);
  return {
    ...base,
    hmacSig: routingHmac(loadCA().overlaySecret, canon),
  };
}

/** Upsert routing row and re-sign file. Caller must sync chain separately. Returns metadata hash for registerNamespace/updateNamespaceBinding. */
export function upsertRoutingPayload(
  cfg: LatticeNodeYaml | null,
  payload: RoutingPayload,
  limits: RoutingCacheLimits = {},
): { metadataHash: string; cachePath: string } {
  const cachePath = routingCacheDiskPath(cfg);
  const normalized = normalizeRoutingPayload(payload);
  let base: Omit<RoutingCacheFile, 'hmacSig'>;
  try {
    const cur = readRoutingCacheFile(cfg);
    if (cur) {
      const { hmacSig: _omit, ...rest } = cur;
      base = rest;
    } else {
      base = emptyRoutingBase();
    }
  } catch {
    base = emptyRoutingBase();
  }
  const maxRoutes = validRouteLimit(limits.maxRoutes ?? routingCacheMaxRoutesFromEnv());
  if (!base.routes[normalized.fqdn] && Object.keys(base.routes).length >= maxRoutes) {
    throw new Error(`Routing cache capacity reached (${maxRoutes} routes); shard or evict inactive routes`);
  }
  base.routes[normalized.fqdn] = {
    payload: normalized,
    updatedAt: new Date().toISOString(),
  };
  writeAtomic(cachePath, seal(base));
  return { metadataHash: routingCommitmentHex(normalized), cachePath };
}

function validRouteLimit(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > HARD_MAX_ROUTING_CACHE_MAX_ROUTES) {
    throw new Error(`Routing cache maxRoutes must be between 1 and ${HARD_MAX_ROUTING_CACHE_MAX_ROUTES}`);
  }
  return value;
}

export function upsertLatticeNodeLocalRecord(
  cfg: LatticeNodeYaml | null,
  nodeLabel: string,
  row: Omit<RoutingCacheFile['latticeNodes'][string], 'updatedAt'>,
  limits: RoutingCacheLimits = {},
): { cachePath: string } {
  const cachePath = routingCacheDiskPath(cfg);
  let base: Omit<RoutingCacheFile, 'hmacSig'>;
  try {
    const cur = readRoutingCacheFile(cfg);
    if (cur) {
      const { hmacSig: _omit, ...rest } = cur;
      base = rest;
    } else {
      base = emptyRoutingBase();
    }
  } catch {
    base = emptyRoutingBase();
  }
  const normalizedLabel = nodeLabel.trim();
  if (!LATTICE_NODE_LABEL_RE.test(normalizedLabel)) throw new Error('Invalid lattice node label');
  const maxNodes = validRouteLimit(limits.maxLatticeNodes ?? limits.maxRoutes ?? routingCacheMaxRoutesFromEnv());
  if (!base.latticeNodes[normalizedLabel] && Object.keys(base.latticeNodes).length >= maxNodes) {
    throw new Error(`Routing cache lattice-node capacity reached (${maxNodes}); shard bootstrap records by cell`);
  }
  base.latticeNodes[normalizedLabel] = { ...row, updatedAt: new Date().toISOString() };
  writeAtomic(cachePath, seal(base));
  return { cachePath };
}

/** Reject a syntactically valid but oversized signed cache before it becomes resident. */
function assertRoutingCacheCardinality(file: RoutingCacheFile, maxEntries: number): void {
  if (!file || typeof file !== 'object' || !file.routes || typeof file.routes !== 'object' ||
      !file.latticeNodes || typeof file.latticeNodes !== 'object') {
    throw new Error('Routing cache has invalid route or lattice-node table');
  }
  if (Object.keys(file.routes).length > maxEntries) {
    throw new Error(`Routing cache exceeds ${maxEntries} route entries; shard or expire inactive routes`);
  }
  if (Object.keys(file.latticeNodes).length > maxEntries) {
    throw new Error(`Routing cache exceeds ${maxEntries} lattice-node entries; shard bootstrap records by cell`);
  }
}

export function lookupRoutingPayload(
  cfg: LatticeNodeYaml | null,
  fqdn: string,
  opts: { requireLocalSig?: boolean } = {},
): RoutingPayload | undefined {
  const f = fqdn.trim().toLowerCase();
  const cur = readRoutingCacheFile(cfg, opts);
  const payload = cur?.routes[f]?.payload;
  return payload ? normalizeRoutingPayload(payload) : undefined;
}

export function lookupLocalLatticeNodePubkey(cfg: LatticeNodeYaml | null, label: string): string | undefined {
  const row = readRoutingCacheFile(cfg)?.latticeNodes[label.trim()];
  return row?.overlayPubKeyB64;
}

export function exportRoutingBundle(cfg: LatticeNodeYaml | null, fqdn: string): RoutingBundle {
  const payload = lookupRoutingPayload(cfg, fqdn, { requireLocalSig: false });
  if (!payload) throw new Error(`No routing-cache row for ${fqdn}`);
  return {
    version: 1,
    exportedAt: new Date().toISOString(),
    route: payload,
    metadataHash: routingCommitmentHex(payload),
  };
}

export function importRoutingBundle(cfg: LatticeNodeYaml | null, bundle: RoutingBundle): { metadataHash: string; cachePath: string } {
  if (bundle.version !== 1 || !bundle.route) throw new Error('Invalid routing bundle');
  const route = normalizeRoutingPayload(bundle.route);
  const expected = routingCommitmentHex(route);
  if (bundle.metadataHash.toLowerCase() !== expected) {
    throw new Error('Routing bundle metadataHash mismatch');
  }
  return upsertRoutingPayload(cfg, route);
}
