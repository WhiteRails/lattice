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

export const LATTICE_DIR = path.join(os.homedir(), '.lattice');

const dirs = ['ca', 'agents', 'policies', 'services', 'logs', 'revocations', 'evidence'];
const PRIVATE_FILE_MODE = 0o600;
const PRIVATE_DIR_MODE = 0o700;

export interface CAState {
  caId: string;
  publicKey: string;
  privateKey: string;
  overlaySecret: string;
  createdAt: string;
}

export interface AgentState {
  cert: any;
  signedCert?: any;
  publicKey: string;
  privateKey: string;
  createdAt: string;
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

// ─── Agents ──────────────────────────────────────────────────────────────────

export function saveAgent(name: string, data: AgentState): void {
  writePrivateJson(agentPath(name), data);
}

export function loadAgent(name: string): AgentState {
  const f = agentPath(name);
  if (!fs.existsSync(f)) throw new Error(`Agent '${name}' not found`);
  return JSON.parse(fs.readFileSync(f, 'utf-8'));
}

export function agentExists(name: string): boolean {
  return fs.existsSync(agentPath(name));
}

export function listAgents(): string[] {
  const d = path.join(LATTICE_DIR, 'agents');
  if (!fs.existsSync(d)) return [];
  return fs.readdirSync(d).filter(f => f.endsWith('.json')).map(f => f.replace('.json', ''));
}

function agentPath(name: string) {
  return path.join(LATTICE_DIR, 'agents', `${name}.json`);
}

// ─── Services ────────────────────────────────────────────────────────────────

export function saveService(name: string, data: object): void {
  fs.writeFileSync(servicePath(name), JSON.stringify(data, null, 2));
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
  return path.join(LATTICE_DIR, 'services', `${name}.json`);
}

// ─── Revocations ─────────────────────────────────────────────────────────────

export function saveRevocation(name: string): void {
  const f = path.join(LATTICE_DIR, 'revocations', 'list.json');
  const list: string[] = fs.existsSync(f) ? JSON.parse(fs.readFileSync(f, 'utf-8')) : [];
  if (!list.includes(name)) {
    list.push(name);
    fs.writeFileSync(f, JSON.stringify(list, null, 2));
  }
}

export function isRevoked(name: string): boolean {
  const f = path.join(LATTICE_DIR, 'revocations', 'list.json');
  if (!fs.existsSync(f)) return false;
  const list: string[] = JSON.parse(fs.readFileSync(f, 'utf-8'));
  return list.includes(name);
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
