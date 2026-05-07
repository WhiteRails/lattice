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

export const ROUTING_PAYLOAD_VERSION = 2 as const;
export type RoutingPayloadVersion = 1 | typeof ROUTING_PAYLOAD_VERSION;

/** Serialized into chain metadataHash hex (canonical JSON UTF-8, keccak256). */
export interface RoutingPayload {
  version: RoutingPayloadVersion;
  fqdn: string;
  gatewayNodeLabel?: string;
  gatewayPubKeyB64: string;
  gatewayEndpoints: string[];
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
      endpoint?: string;
      roleBitmask?: number;
      tlsFingerprintSha256?: string;
      updatedAt: string;
    }
  >;
  /** HMAC-SHA256(H(overlaySecret-utf8), canonical body) hex for local bootstrap rows. */
  hmacSig?: string;
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
  const normalized: RoutingPayload = {
    version: payload.version ?? ROUTING_PAYLOAD_VERSION,
    fqdn: payload.fqdn.toLowerCase(),
    gatewayPubKeyB64: payload.gatewayPubKeyB64.trim(),
    gatewayEndpoints: payload.gatewayEndpoints.map(e => e.trim()).filter(Boolean),
  };
  const label = payload.gatewayNodeLabel?.trim();
  if (label) normalized.gatewayNodeLabel = label;
  return normalized;
}

export function readRoutingCacheFile(
  cfg: LatticeNodeYaml | null,
  opts: { requireLocalSig?: boolean } = {},
): RoutingCacheFile | null {
  const p = routingCacheDiskPath(cfg);
  if (!fs.existsSync(p)) return null;
  const raw = fs.readFileSync(p, 'utf8');
  const parsed = JSON.parse(raw) as RoutingCacheFile;
  if (!parsed.hmacSig || typeof parsed.hmacSig !== 'string') {
    if (opts.requireLocalSig !== false) throw new Error(`Invalid routing cache (missing hmacSig): ${p}`);
    return parsed;
  }
  const { hmacSig, ...rest } = parsed;
  const canon = canonicalBodyForSig(rest);
  const secret = loadCA().overlaySecret;
  const expected = routingHmac(secret, canon);
  const got = Buffer.from(hmacSig, 'hex');
  const expBuf = Buffer.from(expected, 'hex');
  if (got.length !== expBuf.length || !crypto.timingSafeEqual(got, expBuf)) {
    if (opts.requireLocalSig !== false) throw new Error(`Routing cache HMAC mismatch (tampered or wrong CA?): ${p}`);
  }
  return parsed;
}

function writeAtomic(filePath: string, data: RoutingCacheFile): void {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const tmp = `${filePath}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, filePath);
  fs.chmodSync(filePath, 0o600);
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
export function upsertRoutingPayload(cfg: LatticeNodeYaml | null, payload: RoutingPayload): { metadataHash: string; cachePath: string } {
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
  base.routes[normalized.fqdn] = {
    payload: normalized,
    updatedAt: new Date().toISOString(),
  };
  writeAtomic(cachePath, seal(base));
  return { metadataHash: routingCommitmentHex(normalized), cachePath };
}

export function upsertLatticeNodeLocalRecord(
  cfg: LatticeNodeYaml | null,
  nodeLabel: string,
  row: Omit<RoutingCacheFile['latticeNodes'][string], 'updatedAt'>,
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
  base.latticeNodes[nodeLabel.trim()] = { ...row, updatedAt: new Date().toISOString() };
  writeAtomic(cachePath, seal(base));
  return { cachePath };
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
