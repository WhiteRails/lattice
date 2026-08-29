import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { stableStringify } from './message';
import { LATTICE_DIR, loadCA } from './state';
import type { RoutingCacheFile } from './routing-cache';

export interface CircuitRelayCandidate {
  label: string;
  endpoint: string;
  operatorId: string;
  identityPubKeyB64: string;
  onionPubKeyB64Url: string;
  tlsSpkiSha256?: string;
}

export interface CircuitPath {
  guard: CircuitRelayCandidate;
  middle: CircuitRelayCandidate;
  terminal: CircuitRelayCandidate;
}

export interface CircuitSelectionOptions {
  terminalLabel?: string;
  guardLabels?: readonly string[];
  allowSingleOperatorLoopbackTests?: boolean;
  randomInt?: (maxExclusive: number) => number;
}

const RELAY_ROLE_BIT = 2;
const LABEL_RE = /^[a-z0-9._-]{1,64}$/;
const OPERATOR_RE = /^[a-f0-9]{64}$/;
const RAW_X25519_RE = /^[A-Za-z0-9_-]{43}$/;
const DEFAULT_GUARD_LIFETIME_MS = 30 * 24 * 60 * 60_000;

export function relayCandidatesFromRoutingCache(file: RoutingCacheFile): CircuitRelayCandidate[] {
  const candidates: CircuitRelayCandidate[] = [];
  for (const [label, row] of Object.entries(file.latticeNodes)) {
    if ((row.roleBitmask ?? 0) & RELAY_ROLE_BIT) {
      if (!LABEL_RE.test(label) || !row.endpoint || !row.operatorId || !row.identityPubKeyB64 || !row.onionPubKeyB64Url) continue;
      if (!OPERATOR_RE.test(row.operatorId) || !RAW_X25519_RE.test(row.onionPubKeyB64Url)) continue;
      let endpoint: URL;
      try { endpoint = new URL(row.endpoint); } catch { continue; }
      if (endpoint.protocol !== 'wss:' && endpoint.protocol !== 'ws:') continue;
      candidates.push({
        label,
        endpoint: endpoint.toString(),
        operatorId: row.operatorId,
        identityPubKeyB64: row.identityPubKeyB64,
        onionPubKeyB64Url: row.onionPubKeyB64Url,
        tlsSpkiSha256: row.tlsFingerprintSha256?.toLowerCase().replace(/^0x/, ''),
      });
    }
  }
  return candidates;
}

export function selectCircuitPath(
  candidatesInput: readonly CircuitRelayCandidate[],
  options: CircuitSelectionOptions = {},
): CircuitPath {
  const randomInt = options.randomInt ?? crypto.randomInt;
  const byLabel = new Map(candidatesInput.map(candidate => [candidate.label, validateCandidate(candidate)]));
  const candidates = [...byLabel.values()];
  if (candidates.length < 3) throw new Error('CIRCUIT_UNAVAILABLE: at least three distinct relay nodes are required');
  const terminal = options.terminalLabel
    ? byLabel.get(options.terminalLabel)
    : pick(candidates, randomInt);
  if (!terminal) throw new Error('CIRCUIT_UNAVAILABLE: terminal relay is not in the authenticated directory');

  const guardPool = options.guardLabels?.length
    ? candidates.filter(candidate => options.guardLabels!.includes(candidate.label) && candidate.label !== terminal.label)
    : candidates.filter(candidate => candidate.label !== terminal.label);
  const guard = pick(guardPool.filter(candidate => operatorCompatible(candidate, terminal, options)), randomInt);
  if (!guard) throw new Error('CIRCUIT_UNAVAILABLE: no operator-diverse guard relay');
  const middle = pick(candidates.filter(candidate =>
    candidate.label !== guard.label && candidate.label !== terminal.label &&
    operatorCompatible(candidate, guard, options) && operatorCompatible(candidate, terminal, options)), randomInt);
  if (!middle) throw new Error('CIRCUIT_UNAVAILABLE: no three-operator circuit');
  return { guard, middle, terminal };
}

export class GuardSetStore {
  constructor(
    private readonly filePath = path.join(LATTICE_DIR, 'circuit-guards.json'),
    private readonly lifetimeMs = DEFAULT_GUARD_LIFETIME_MS,
  ) {
    if (!Number.isSafeInteger(lifetimeMs) || lifetimeMs < 24 * 60 * 60_000 || lifetimeMs > DEFAULT_GUARD_LIFETIME_MS) {
      throw new Error('Guard lifetime must be between one and 30 days');
    }
  }

  loadOrSelect(candidates: readonly CircuitRelayCandidate[], count = 3, now = Date.now()): string[] {
    if (!Number.isInteger(count) || count < 1 || count > 3) throw new Error('Guard set size must be 1-3');
    const eligible = candidates.map(validateCandidate);
    const existing = this.read(now).filter(label => eligible.some(candidate => candidate.label === label));
    if (existing.length >= count) return existing.slice(0, count);
    const selected = [...existing];
    const usedOperators = new Set(
      eligible.filter(candidate => selected.includes(candidate.label)).map(candidate => candidate.operatorId),
    );
    const remaining = eligible.filter(candidate => !selected.includes(candidate.label) && !usedOperators.has(candidate.operatorId));
    while (selected.length < count && remaining.length) {
      const index = crypto.randomInt(remaining.length);
      const [candidate] = remaining.splice(index, 1);
      if (!candidate) break;
      selected.push(candidate.label);
      usedOperators.add(candidate.operatorId);
      for (let i = remaining.length - 1; i >= 0; i--) {
        if (remaining[i]!.operatorId === candidate.operatorId) remaining.splice(i, 1);
      }
    }
    if (selected.length < count) throw new Error('CIRCUIT_UNAVAILABLE: insufficient operator-diverse guards');
    this.write(selected, now);
    return selected;
  }

  private read(now: number): string[] {
    if (!fs.existsSync(this.filePath)) return [];
    try {
      const stat = fs.statSync(this.filePath);
      if (!stat.isFile() || stat.size > 16 * 1024 || (stat.mode & 0o077) !== 0) return [];
      const parsed = JSON.parse(fs.readFileSync(this.filePath, 'utf8')) as {
        version: number; selectedAt: string; expiresAt: string; labels: string[]; hmac: string;
      };
      const body = { version: parsed.version, selectedAt: parsed.selectedAt, expiresAt: parsed.expiresAt, labels: parsed.labels };
      if (parsed.version !== 1 || !Array.isArray(parsed.labels) || new Date(parsed.expiresAt).getTime() <= now) return [];
      const expected = guardHmac(body);
      const provided = Buffer.from(parsed.hmac ?? '', 'hex');
      const wanted = Buffer.from(expected, 'hex');
      if (provided.length !== wanted.length || !crypto.timingSafeEqual(provided, wanted)) return [];
      return parsed.labels.filter(label => LABEL_RE.test(label));
    } catch {
      return [];
    }
  }

  private write(labels: string[], now: number): void {
    const body = {
      version: 1,
      selectedAt: new Date(now).toISOString(),
      expiresAt: new Date(now + this.lifetimeMs).toISOString(),
      labels,
    };
    const value = { ...body, hmac: guardHmac(body) };
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true, mode: 0o700 });
    const temp = `${this.filePath}.tmp-${process.pid}`;
    fs.writeFileSync(temp, JSON.stringify(value, null, 2), { mode: 0o600 });
    fs.renameSync(temp, this.filePath);
    fs.chmodSync(this.filePath, 0o600);
  }
}

function validateCandidate(candidate: CircuitRelayCandidate): CircuitRelayCandidate {
  if (!LABEL_RE.test(candidate.label) || !OPERATOR_RE.test(candidate.operatorId) || !RAW_X25519_RE.test(candidate.onionPubKeyB64Url)) {
    throw new Error(`Invalid circuit relay candidate: ${candidate.label}`);
  }
  const endpoint = new URL(candidate.endpoint);
  if (endpoint.protocol !== 'wss:' && !(endpoint.protocol === 'ws:' && isLoopback(endpoint.hostname))) {
    throw new Error(`Circuit relay endpoint must use WSS: ${candidate.label}`);
  }
  if (!candidate.identityPubKeyB64 || Buffer.from(candidate.identityPubKeyB64, 'base64').length < 32) {
    throw new Error(`Circuit relay identity is invalid: ${candidate.label}`);
  }
  if (endpoint.protocol === 'wss:' && !/^[a-f0-9]{64}$/.test(candidate.tlsSpkiSha256 ?? '')) {
    throw new Error(`Circuit relay TLS SPKI pin is missing: ${candidate.label}`);
  }
  return { ...candidate, endpoint: endpoint.toString() };
}

function operatorCompatible(
  left: CircuitRelayCandidate,
  right: CircuitRelayCandidate,
  options: CircuitSelectionOptions,
): boolean {
  if (left.operatorId !== right.operatorId) return true;
  if (!options.allowSingleOperatorLoopbackTests) return false;
  return isLoopback(new URL(left.endpoint).hostname) && isLoopback(new URL(right.endpoint).hostname);
}

function isLoopback(hostname: string): boolean {
  const host = hostname.replace(/^\[|]$/g, '').toLowerCase();
  return host === '127.0.0.1' || host === '::1' || host === 'localhost';
}

function pick<T>(values: readonly T[], randomInt: (maxExclusive: number) => number): T | undefined {
  return values.length ? values[randomInt(values.length)] : undefined;
}

function guardHmac(body: object): string {
  return crypto.createHmac('sha256', Buffer.from(loadCA().overlaySecret, 'utf8'))
    .update(stableStringify(body), 'utf8').digest('hex');
}
