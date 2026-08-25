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

export interface CAState {
  caId: string;
  publicKey: string;
  privateKey: string;
  overlaySecret: string;
  createdAt: string;
  overlayNodeKeyPair?: NodeKeyPair;  // X25519 keys for per-peer ECDH sessions
}

export interface AgentState {
  cert: any;
  signedCert?: any;
  publicKey: string;
  privateKey: string;
  createdAt: string;
}

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
}

export function loadCA(): CAState {
  const f = path.join(LATTICE_DIR, 'ca', 'ca.json');
  if (!fs.existsSync(f)) throw new Error('Lattice not initialized. Run: lattice init');
  const state = JSON.parse(fs.readFileSync(f, 'utf-8'));
  if (!state.privateKey || !state.overlaySecret) {
    throw new Error('Lattice CA state is incomplete. Re-run lattice init in a clean state or migrate ca.json.');
  }
  return state;
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
  writePrivateJson(agentPath(normalizeAgentName(name)), data);
}

export function loadAgent(name: string): AgentState {
  const canonicalName = normalizeAgentName(name);
  const f = agentPath(canonicalName);
  if (!fs.existsSync(f)) throw new Error(`Agent '${canonicalName}' not found`);
  return JSON.parse(fs.readFileSync(f, 'utf-8'));
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

export function saveRevocation(name: string): void {
  const canonicalName = normalizeAgentName(name);
  const f = path.join(LATTICE_DIR, 'revocations', 'list.json');
  const list: string[] = fs.existsSync(f) ? JSON.parse(fs.readFileSync(f, 'utf-8')) : [];
  if (!list.includes(canonicalName)) {
    list.push(canonicalName);
    fs.writeFileSync(f, JSON.stringify(list, null, 2));
  }
}

export function isRevoked(name: string): boolean {
  let canonicalName: string;
  try {
    canonicalName = normalizeAgentName(name);
  } catch {
    return true;
  }
  const f = path.join(LATTICE_DIR, 'revocations', 'list.json');
  if (!fs.existsSync(f)) return false;
  const list: string[] = JSON.parse(fs.readFileSync(f, 'utf-8'));
  return list.includes(canonicalName);
}

export function listRevocations(): string[] {
  const f = path.join(LATTICE_DIR, 'revocations', 'list.json');
  if (!fs.existsSync(f)) return [];
  return JSON.parse(fs.readFileSync(f, 'utf-8'));
}

// ─── Action Log ──────────────────────────────────────────────────────────────

export function appendLog(entry: object): void {
  const f = path.join(LATTICE_DIR, 'logs', 'actions.jsonl');
  fs.appendFileSync(f, JSON.stringify(entry) + '\n');
}

export function tailLog(n: number = 50): object[] {
  const f = path.join(LATTICE_DIR, 'logs', 'actions.jsonl');
  if (!fs.existsSync(f)) return [];
  const lines = fs.readFileSync(f, 'utf-8').trim().split('\n').filter(Boolean);
  return lines.slice(-n).map(l => JSON.parse(l));
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
