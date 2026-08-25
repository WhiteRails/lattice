/**
 * daemon/state.ts — Lattice local state manager
 *
 * Manages the ~/.lattice/ directory structure:
 *
 *   ~/.lattice/
 *     ca/            ca.json  (cert + private key)
 *     agents/        {name}/cert.json
 *     policies/      {name}.yaml
 *     services/      {name}.json
 *     logs/          actions.jsonl
 *     revocations/   list.json
 */

import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { PowerAccumulationTracker } from '../core/pas';
import { NodeKeyPair, generateNodeKeyPair } from './session';

export const LATTICE_DIR =
  typeof process.env.LATTICE_HOME === 'string' && process.env.LATTICE_HOME.trim().length > 0 ?
    path.resolve(process.env.LATTICE_HOME.trim())
  : path.join(os.homedir(), '.lattice');

const dirs = ['ca', 'agents', 'policies', 'services', 'logs', 'revocations', 'evidence'];
const PRIVATE_FILE_MODE = 0o600;
const PRIVATE_DIR_MODE = 0o700;
const DEFAULT_LOCAL_REVOCATION_MAX_ENTRIES = 100_000;
const MIN_LOCAL_REVOCATION_MAX_ENTRIES = 1_000;
const MAX_LOCAL_REVOCATION_MAX_ENTRIES = 1_000_000;
const DEFAULT_ENTRY_AGENT_CACHE_MAX_ENTRIES = 8_192;
const MIN_ENTRY_AGENT_CACHE_MAX_ENTRIES = 32;
const MAX_ENTRY_AGENT_CACHE_MAX_ENTRIES = 65_536;
const MAX_AGENT_STATE_FILE_BYTES = 64 * 1024;
const MAX_CA_STATE_FILE_BYTES = 64 * 1024;
const LOCAL_STATE_REVALIDATE_MS = 1_000;
export const MAX_TAIL_LOG_ENTRIES = 10_000;
export const MAX_TAIL_LOG_BYTES = 32 * 1024 * 1024;

export interface CAState {
  caId: string;
  publicKey: string;
  privateKey: string;
  overlaySecret: string;
  createdAt: string;
  overlayNodeKeyPair?: NodeKeyPair;  // X25519 keys for per-peer ECDH sessions
}

interface CachedCAState {
  state: CAState | null;
  checkedAtMs: number;
  mtimeMs?: number;
  size?: number;
}

let cachedCAState: CachedCAState | undefined;

export interface AgentState {
  cert: any;
  signedCert?: any;
  publicKey: string;
  privateKey: string;
  createdAt: string;
}

/** The only part of local agent state required on Entry's data path. */
export interface AgentPublicIdentity {
  publicKey: string;
  signedCert?: unknown;
}

interface CachedAgentIdentity {
  identity: AgentPublicIdentity | null;
  checkedAtMs: number;
  mtimeMs?: number;
  size?: number;
}

const cachedAgentIdentities = new Map<string, CachedAgentIdentity>();

const AGENT_NAME_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/;

/**
 * Agent names are security principals and filenames. Keep one canonical spelling
 * so authorization, revocation, and filesystem access cannot diverge.
 */
export function normalizeAgentName(name: string): string {
  const normalized = name.trim();
  if (!AGENT_NAME_RE.test(normalized)) {
    throw new Error('Invalid agent name: use 1-64 lowercase letters, digits, _ or -');
  }
  return normalized;
}

function writePrivateJson(file: string, data: object): void {
  fs.writeFileSync(file, JSON.stringify(data, null, 2), { mode: PRIVATE_FILE_MODE });
  fs.chmodSync(file, PRIVATE_FILE_MODE);
}

export function initDirs(): void {
  if (!fs.existsSync(LATTICE_DIR)) {
    fs.mkdirSync(LATTICE_DIR, { recursive: true, mode: PRIVATE_DIR_MODE });
  }
  fs.chmodSync(LATTICE_DIR, PRIVATE_DIR_MODE);
  for (const d of dirs) {
    const full = path.join(LATTICE_DIR, d);
    if (!fs.existsSync(full)) fs.mkdirSync(full, { recursive: true, mode: PRIVATE_DIR_MODE });
    fs.chmodSync(full, PRIVATE_DIR_MODE);
  }
}

export function isInitialized(): boolean {
  return fs.existsSync(path.join(LATTICE_DIR, 'ca', 'ca.json'));
}

// ─── CA ──────────────────────────────────────────────────────────────────────

export function saveCA(data: CAState): void {
  writePrivateJson(path.join(LATTICE_DIR, 'ca', 'ca.json'), data);
  cachedCAState = { state: data, checkedAtMs: Date.now() };
}

export function loadCA(): CAState {
  const f = path.join(LATTICE_DIR, 'ca', 'ca.json');
  const now = Date.now();
  if (cachedCAState && now - cachedCAState.checkedAtMs < LOCAL_STATE_REVALIDATE_MS) {
    return cachedCA(cachedCAState);
  }
  let stat: fs.Stats;
  try {
    stat = fs.statSync(f);
  } catch {
    cachedCAState = { state: null, checkedAtMs: now };
    throw new Error('Lattice not initialized. Run: lattice init');
  }
  if (!Number.isSafeInteger(stat.size) || stat.size < 0 || stat.size > MAX_CA_STATE_FILE_BYTES) {
    cachedCAState = { state: null, checkedAtMs: now, mtimeMs: stat.mtimeMs, size: stat.size };
    throw new Error(`Lattice CA state exceeds ${MAX_CA_STATE_FILE_BYTES} bytes`);
  }
  if (cachedCAState && cachedCAState.mtimeMs === stat.mtimeMs && cachedCAState.size === stat.size) {
    cachedCAState.checkedAtMs = now;
    return cachedCA(cachedCAState);
  }
  let state: CAState;
  try {
    state = JSON.parse(fs.readFileSync(f, 'utf-8')) as CAState;
  } catch {
    cachedCAState = { state: null, checkedAtMs: now, mtimeMs: stat.mtimeMs, size: stat.size };
    throw new Error('Lattice CA state is invalid');
  }
  if (!state.privateKey || !state.overlaySecret) {
    throw new Error('Lattice CA state is incomplete. Re-run lattice init in a clean state or migrate ca.json.');
  }
  cachedCAState = { state, checkedAtMs: now, mtimeMs: stat.mtimeMs, size: stat.size };
  return state;
}

function cachedCA(cached: CachedCAState): CAState {
  if (!cached.state) throw new Error('Lattice CA state is unavailable');
  return cached.state;
}

export function getOrCreateOverlayKeyPair(): NodeKeyPair {
  const ca = loadCA();
  if (ca.overlayNodeKeyPair) return ca.overlayNodeKeyPair;
  const kp = generateNodeKeyPair();
  saveCA({ ...ca, overlayNodeKeyPair: kp });
  return kp;
}

// ─── Agents ──────────────────────────────────────────────────────────────────

export function saveAgent(name: string, data: AgentState): void {
  const file = agentPath(normalizeAgentName(name));
  writePrivateJson(file, data);
  cachedAgentIdentities.delete(file);
}

export function loadAgent(name: string): AgentState {
  const canonicalName = normalizeAgentName(name);
  const f = agentPath(canonicalName);
  if (!fs.existsSync(f)) throw new Error(`Agent '${canonicalName}' not found`);
  return JSON.parse(fs.readFileSync(f, 'utf-8'));
}

/**
 * Bounded LRU cache for Entry signature verification. It intentionally keeps
 * no agent private key in the long-lived network process and revalidates file
 * state at most once per second instead of doing sync I/O for every request.
 */
export function loadAgentPublicIdentity(name: string): AgentPublicIdentity {
  const canonicalName = normalizeAgentName(name);
  const file = agentPath(canonicalName);
  const now = Date.now();
  const cached = cachedAgentIdentities.get(file);
  if (cached && now - cached.checkedAtMs < LOCAL_STATE_REVALIDATE_MS) {
    return cachedAgentIdentity(cached, canonicalName);
  }
  let stat: fs.Stats;
  try {
    stat = fs.statSync(file);
  } catch {
    cacheAgentIdentity(file, { identity: null, checkedAtMs: now });
    throw new Error(`Agent '${canonicalName}' not found`);
  }
  if (!Number.isSafeInteger(stat.size) || stat.size < 0 || stat.size > MAX_AGENT_STATE_FILE_BYTES) {
    cacheAgentIdentity(file, { identity: null, checkedAtMs: now, mtimeMs: stat.mtimeMs, size: stat.size });
    throw new Error(`Agent '${canonicalName}' state exceeds ${MAX_AGENT_STATE_FILE_BYTES} bytes`);
  }
  if (cached && cached.mtimeMs === stat.mtimeMs && cached.size === stat.size) {
    cached.checkedAtMs = now;
    return cachedAgentIdentity(cached, canonicalName);
  }
  let parsed: AgentState;
  try {
    parsed = JSON.parse(fs.readFileSync(file, 'utf-8')) as AgentState;
  } catch {
    cacheAgentIdentity(file, { identity: null, checkedAtMs: now, mtimeMs: stat.mtimeMs, size: stat.size });
    throw new Error(`Agent '${canonicalName}' state is invalid`);
  }
  const publicKey = typeof parsed.publicKey === 'string' && parsed.publicKey.length
    ? parsed.publicKey
    : typeof parsed.cert?.public_key === 'string' && parsed.cert.public_key.length
      ? parsed.cert.public_key
      : undefined;
  if (!publicKey || publicKey.length > 8_192) {
    cacheAgentIdentity(file, { identity: null, checkedAtMs: now, mtimeMs: stat.mtimeMs, size: stat.size });
    throw new Error(`Agent '${canonicalName}' state has no valid public key`);
  }
  const identity = { publicKey, signedCert: parsed.signedCert };
  cacheAgentIdentity(file, { identity, checkedAtMs: now, mtimeMs: stat.mtimeMs, size: stat.size });
  return identity;
}

export function entryAgentCacheMaxEntriesFromEnv(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.LATTICE_ENTRY_AGENT_CACHE_MAX_ENTRIES;
  if (raw === undefined || raw.trim() === '') return DEFAULT_ENTRY_AGENT_CACHE_MAX_ENTRIES;
  if (!/^[0-9]+$/.test(raw.trim())) throw new Error('LATTICE_ENTRY_AGENT_CACHE_MAX_ENTRIES must be an integer');
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < MIN_ENTRY_AGENT_CACHE_MAX_ENTRIES || value > MAX_ENTRY_AGENT_CACHE_MAX_ENTRIES) {
    throw new Error(`LATTICE_ENTRY_AGENT_CACHE_MAX_ENTRIES must be between ${MIN_ENTRY_AGENT_CACHE_MAX_ENTRIES} and ${MAX_ENTRY_AGENT_CACHE_MAX_ENTRIES}`);
  }
  return value;
}

function cachedAgentIdentity(cached: CachedAgentIdentity, name: string): AgentPublicIdentity {
  if (!cached.identity) throw new Error(`Agent '${name}' not found or invalid`);
  return cached.identity;
}

function cacheAgentIdentity(file: string, entry: CachedAgentIdentity): void {
  cachedAgentIdentities.delete(file);
  const maxEntries = entryAgentCacheMaxEntriesFromEnv();
  while (cachedAgentIdentities.size >= maxEntries) {
    const oldest = cachedAgentIdentities.keys().next().value as string | undefined;
    if (!oldest) break;
    cachedAgentIdentities.delete(oldest);
  }
  cachedAgentIdentities.set(file, entry);
}

export function agentExists(name: string): boolean {
  try {
    return fs.existsSync(agentPath(normalizeAgentName(name)));
  } catch {
    return false;
  }
}

export function listAgents(): string[] {
  const d = path.join(LATTICE_DIR, 'agents');
  if (!fs.existsSync(d)) return [];
  return fs.readdirSync(d).filter(f => f.endsWith('.json')).map(f => f.replace('.json', ''));
}

function agentPath(name: string) {
  const base = path.resolve(LATTICE_DIR, 'agents');
  const candidate = path.resolve(base, `${name}.json`);
  if (!candidate.startsWith(base + path.sep)) throw new Error('Agent path escaped state directory');
  return candidate;
}

// ─── Services ────────────────────────────────────────────────────────────────

export function saveService(name: string, data: object): void {
  fs.writeFileSync(servicePath(name), JSON.stringify(data, null, 2), { mode: PRIVATE_FILE_MODE });
}

export function loadService(name: string): any {
  const f = servicePath(name);
  if (!fs.existsSync(f)) throw new Error(`Service '${name}' not found`);
  return JSON.parse(fs.readFileSync(f, 'utf-8'));
}

export function serviceExists(name: string): boolean {
  return fs.existsSync(servicePath(name));
}

export function listServices(): string[] {
  const d = path.join(LATTICE_DIR, 'services');
  if (!fs.existsSync(d)) return [];
  return fs.readdirSync(d).filter(f => f.endsWith('.json')).map(f => f.replace('.json', ''));
}

function servicePath(name: string) {
  const canonical = normalizeAgentName(name);
  const base = path.resolve(LATTICE_DIR, 'services');
  const candidate = path.resolve(base, `${canonical}.json`);
  if (!candidate.startsWith(base + path.sep)) throw new Error('Service path escaped state directory');
  return candidate;
}

// ─── Revocations ─────────────────────────────────────────────────────────────

interface CachedRevocations {
  file: string;
  checkedAtMs: number;
  mtimeMs: number;
  size: number;
  names: Set<string>;
}

let cachedRevocations: CachedRevocations | undefined;

export function localRevocationMaxEntriesFromEnv(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.LATTICE_LOCAL_REVOCATION_MAX_ENTRIES;
  if (raw === undefined || raw.trim() === '') return DEFAULT_LOCAL_REVOCATION_MAX_ENTRIES;
  if (!/^[0-9]+$/.test(raw.trim())) throw new Error('LATTICE_LOCAL_REVOCATION_MAX_ENTRIES must be an integer');
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < MIN_LOCAL_REVOCATION_MAX_ENTRIES || value > MAX_LOCAL_REVOCATION_MAX_ENTRIES) {
    throw new Error(`LATTICE_LOCAL_REVOCATION_MAX_ENTRIES must be between ${MIN_LOCAL_REVOCATION_MAX_ENTRIES} and ${MAX_LOCAL_REVOCATION_MAX_ENTRIES}`);
  }
  return value;
}

function revocationPath(): string {
  return path.join(LATTICE_DIR, 'revocations', 'list.json');
}

/** Read once per file version; malformed or oversized local revocation state is unsafe. */
function loadLocalRevocations(): Set<string> {
  const file = revocationPath();
  const now = Date.now();
  if (cachedRevocations && cachedRevocations.file === file && now - cachedRevocations.checkedAtMs < LOCAL_STATE_REVALIDATE_MS) {
    return cachedRevocations.names;
  }
  let stat: fs.Stats;
  try {
    stat = fs.statSync(file);
  } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      cachedRevocations = undefined;
      return new Set();
    }
    throw error;
  }
  if (cachedRevocations && cachedRevocations.file === file &&
      cachedRevocations.mtimeMs === stat.mtimeMs && cachedRevocations.size === stat.size) {
    cachedRevocations.checkedAtMs = now;
    return cachedRevocations.names;
  }
  const parsed: unknown = JSON.parse(fs.readFileSync(file, 'utf-8'));
  if (!Array.isArray(parsed)) throw new Error('Local revocation list must be an array');
  const maxEntries = localRevocationMaxEntriesFromEnv();
  if (parsed.length > maxEntries) throw new Error(`Local revocation list exceeds capacity (${maxEntries})`);
  const names = new Set<string>();
  for (const item of parsed) {
    if (typeof item !== 'string') throw new Error('Local revocation list contains an invalid principal');
    names.add(normalizeAgentName(item));
  }
  if (names.size > maxEntries) throw new Error(`Local revocation list exceeds capacity (${maxEntries})`);
  cachedRevocations = { file, checkedAtMs: now, mtimeMs: stat.mtimeMs, size: stat.size, names };
  return names;
}

function writeLocalRevocations(names: Set<string>): void {
  const file = revocationPath();
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: PRIVATE_DIR_MODE });
  const serialized = JSON.stringify([...names].sort(), null, 2);
  const temp = `${file}.${process.pid}.${Math.random().toString(16).slice(2)}.tmp`;
  fs.writeFileSync(temp, serialized, { mode: PRIVATE_FILE_MODE });
  fs.renameSync(temp, file);
  fs.chmodSync(file, PRIVATE_FILE_MODE);
  const stat = fs.statSync(file);
  cachedRevocations = { file, checkedAtMs: Date.now(), mtimeMs: stat.mtimeMs, size: stat.size, names };
}

export function saveRevocation(name: string): void {
  const canonicalName = normalizeAgentName(name);
  const names = loadLocalRevocations();
  if (!names.has(canonicalName)) {
    if (names.size >= localRevocationMaxEntriesFromEnv()) {
      throw new Error(`Local revocation capacity reached (${names.size}); distribute revocation state to another cell`);
    }
    names.add(canonicalName);
    writeLocalRevocations(names);
  }
}

export function isRevoked(name: string): boolean {
  let canonicalName: string;
  try {
    canonicalName = normalizeAgentName(name);
  } catch {
    return true;
  }
  try {
    return loadLocalRevocations().has(canonicalName);
  } catch {
    // An unreadable, tampered or oversized revocation list must never cause a
    // principal to be treated as safe.
    return true;
  }
}

export function listRevocations(): string[] {
  return [...loadLocalRevocations()].sort();
}

// ─── Action Log ──────────────────────────────────────────────────────────────

export function appendLog(entry: object): void {
  const f = path.join(LATTICE_DIR, 'logs', 'actions.jsonl');
  fs.appendFileSync(f, JSON.stringify(entry) + '\n');
}

export function tailLog(n: number = 50): object[] {
  const f = path.join(LATTICE_DIR, 'logs', 'actions.jsonl');
  if (!fs.existsSync(f)) return [];
  if (!Number.isSafeInteger(n) || n < 1 || n > MAX_TAIL_LOG_ENTRIES) {
    throw new Error(`Log tail count must be between 1 and ${MAX_TAIL_LOG_ENTRIES}`);
  }
  const size = fs.statSync(f).size;
  if (size === 0) return [];
  const start = Math.max(0, size - MAX_TAIL_LOG_BYTES);
  const bytes = Buffer.allocUnsafe(size - start);
  const fd = fs.openSync(f, 'r');
  try {
    let offset = 0;
    while (offset < bytes.length) {
      const read = fs.readSync(fd, bytes, offset, bytes.length - offset, start + offset);
      if (read === 0) break;
      offset += read;
    }
    if (offset !== bytes.length) throw new Error('Could not read complete action-log tail');
  } finally {
    fs.closeSync(fd);
  }
  let text = bytes.toString('utf8');
  if (start > 0) {
    // The bounded window may begin in a JSONL record. Never parse that fragment.
    const firstBoundary = text.indexOf('\n');
    if (firstBoundary === -1) {
      throw new Error(`Action-log tail exceeds ${MAX_TAIL_LOG_BYTES} bytes before a complete record boundary`);
    }
    text = text.slice(firstBoundary + 1);
  }
  const lines = text.trim().split('\n').filter(Boolean);
  if (start > 0 && lines.length < n) {
    throw new Error(`Requested log tail exceeds ${MAX_TAIL_LOG_BYTES} bytes; query the archived journal instead`);
  }
  return lines.slice(-n).map(line => JSON.parse(line));
}

export function logPath(): string {
  return path.join(LATTICE_DIR, 'logs', 'actions.jsonl');
}

// ─── PAS State ───────────────────────────────────────────────────────────────

export const PAS_STATE_PATH = path.join(LATTICE_DIR, 'pas-state.json');

export function savePAS(tracker: PowerAccumulationTracker, hmacKey: string): void {
  tracker.save(PAS_STATE_PATH, hmacKey);
}

export function loadPAS(tracker: PowerAccumulationTracker, hmacKey: string): void {
  if (fs.existsSync(PAS_STATE_PATH)) {
    tracker.load(PAS_STATE_PATH, hmacKey);
  }
}
