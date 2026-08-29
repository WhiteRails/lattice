import * as crypto from 'crypto';
import * as fs from 'fs';
import * as path from 'path';
import { spawn } from 'child_process';
import { LATTICE_DIR } from './state';
import { deriveRawX25519, generateRawX25519KeyPair } from './onion-handshake';
import { generateHpkeKeyPair, openHpkeJson, type HpkeEnvelope } from './hpke-envelope';

export type NodeKeyPurpose = 'identity' | 'onion' | 'gateway-encryption';
export type NodeKeyAlgorithm = 'ed25519' | 'x25519-ntor' | 'x25519-hpke';
export type NodeKeyStatus = 'active' | 'retired';

export interface NodeKeyDescriptor {
  version: 1;
  keyId: string;
  purpose: NodeKeyPurpose;
  algorithm: NodeKeyAlgorithm;
  publicKey: string;
  createdAt: string;
  status: NodeKeyStatus;
  retireAfter?: string;
}

interface LocalNodeKeyRecord extends NodeKeyDescriptor {
  privateKey: string;
}

interface NodeKeyIndex {
  version: 1;
  current: Partial<Record<NodeKeyPurpose, string>>;
}

export interface NodeCryptoBackend {
  readonly type: 'local' | 'plugin';
  ensureKeys(purposes: readonly NodeKeyPurpose[]): Promise<NodeKeyDescriptor[]>;
  currentKey(purpose: NodeKeyPurpose): Promise<NodeKeyDescriptor>;
  getPublicKey(keyId: string): Promise<NodeKeyDescriptor>;
  signEd25519(keyId: string, payload: Buffer): Promise<Buffer>;
  deriveX25519(keyId: string, peerPublicKey: string): Promise<Buffer>;
  hpkeOpen<T>(keyId: string, envelope: HpkeEnvelope): Promise<T>;
  rotate(purpose: NodeKeyPurpose, overlapMs?: number): Promise<NodeKeyDescriptor>;
}

const PRIVATE_DIR_MODE = 0o700;
const PRIVATE_FILE_MODE = 0o600;
const DEFAULT_KEY_OVERLAP_MS = 60 * 60_000;
const KEY_ID_RE = /^[a-f0-9]{64}$/;
const MAX_PLUGIN_OUTPUT_BYTES = 2 * 1024 * 1024;

export class LocalNodeCryptoBackend implements NodeCryptoBackend {
  readonly type = 'local' as const;
  private readonly keyDir: string;
  private readonly indexPath: string;

  constructor(keyDir = path.join(LATTICE_DIR, 'keys')) {
    this.keyDir = path.resolve(keyDir);
    this.indexPath = path.join(this.keyDir, 'index.json');
    ensurePrivateDir(this.keyDir);
  }

  async ensureKeys(purposes: readonly NodeKeyPurpose[]): Promise<NodeKeyDescriptor[]> {
    const index = this.loadIndex();
    const descriptors: NodeKeyDescriptor[] = [];
    for (const purpose of purposes) {
      const currentId = index.current[purpose];
      if (currentId) {
        const existing = this.loadRecord(currentId);
        if (existing.purpose !== purpose || existing.status !== 'active') {
          throw new Error(`Current ${purpose} key is invalid`);
        }
        descriptors.push(publicDescriptor(existing));
        continue;
      }
      const record = await generateRecord(purpose);
      this.saveRecord(record);
      index.current[purpose] = record.keyId;
      descriptors.push(publicDescriptor(record));
    }
    this.saveIndex(index);
    return descriptors;
  }

  async currentKey(purpose: NodeKeyPurpose): Promise<NodeKeyDescriptor> {
    await this.ensureKeys([purpose]);
    const id = this.loadIndex().current[purpose];
    if (!id) throw new Error(`No current ${purpose} key`);
    return publicDescriptor(this.loadRecord(id));
  }

  async getPublicKey(keyId: string): Promise<NodeKeyDescriptor> {
    return publicDescriptor(this.loadRecord(keyId));
  }

  async signEd25519(keyId: string, payload: Buffer): Promise<Buffer> {
    const record = this.loadRecord(keyId);
    if (record.algorithm !== 'ed25519') throw new Error('Key does not support Ed25519 signing');
    const key = crypto.createPrivateKey({ key: Buffer.from(record.privateKey, 'base64'), format: 'der', type: 'pkcs8' });
    return crypto.sign(null, payload, key);
  }

  async deriveX25519(keyId: string, peerPublicKey: string): Promise<Buffer> {
    const record = this.loadRecord(keyId);
    if (record.algorithm !== 'x25519-ntor') throw new Error('Key does not support ntor X25519 derivation');
    return deriveRawX25519(record.privateKey, peerPublicKey);
  }

  async hpkeOpen<T>(keyId: string, envelope: HpkeEnvelope): Promise<T> {
    const record = this.loadRecord(keyId);
    if (record.algorithm !== 'x25519-hpke') throw new Error('Key does not support HPKE decryption');
    if (record.keyId !== envelope.key_id) throw new Error('HPKE envelope key id mismatch');
    if (record.status === 'retired' && (!record.retireAfter || new Date(record.retireAfter).getTime() <= Date.now())) {
      throw new Error('Retired HPKE key overlap has expired');
    }
    return openHpkeJson<T>(record.privateKey, envelope);
  }

  async rotate(purpose: NodeKeyPurpose, overlapMs = DEFAULT_KEY_OVERLAP_MS): Promise<NodeKeyDescriptor> {
    if (!Number.isSafeInteger(overlapMs) || overlapMs < 60_000 || overlapMs > 24 * 60 * 60_000) {
      throw new Error('Key overlap must be between one minute and 24 hours');
    }
    await this.ensureKeys([purpose]);
    const index = this.loadIndex();
    const previousId = index.current[purpose];
    if (previousId) {
      const previous = this.loadRecord(previousId);
      previous.status = 'retired';
      previous.retireAfter = new Date(Date.now() + overlapMs).toISOString();
      this.saveRecord(previous);
    }
    const next = await generateRecord(purpose);
    this.saveRecord(next);
    index.current[purpose] = next.keyId;
    this.saveIndex(index);
    return publicDescriptor(next);
  }

  private loadIndex(): NodeKeyIndex {
    if (!fs.existsSync(this.indexPath)) return { version: 1, current: {} };
    assertPrivateRegularFile(this.indexPath);
    const parsed = JSON.parse(fs.readFileSync(this.indexPath, 'utf8')) as NodeKeyIndex;
    if (parsed.version !== 1 || !parsed.current || typeof parsed.current !== 'object') throw new Error('Invalid node key index');
    return parsed;
  }

  private saveIndex(index: NodeKeyIndex): void {
    writePrivateJsonAtomic(this.indexPath, index);
  }

  private loadRecord(keyId: string): LocalNodeKeyRecord {
    if (!KEY_ID_RE.test(keyId)) throw new Error('Invalid node key id');
    const keyPath = path.join(this.keyDir, `${keyId}.json`);
    assertPrivateRegularFile(keyPath);
    const record = JSON.parse(fs.readFileSync(keyPath, 'utf8')) as LocalNodeKeyRecord;
    validateRecord(record, keyId);
    return record;
  }

  private saveRecord(record: LocalNodeKeyRecord): void {
    validateRecord(record, record.keyId);
    writePrivateJsonAtomic(path.join(this.keyDir, `${record.keyId}.json`), record);
  }
}

export class PluginNodeCryptoBackend implements NodeCryptoBackend {
  readonly type = 'plugin' as const;
  constructor(private readonly pluginCommand: string) {
    if (!pluginCommand.trim()) throw new Error('Node crypto plugin command is required');
  }

  ensureKeys(purposes: readonly NodeKeyPurpose[]): Promise<NodeKeyDescriptor[]> {
    return this.call('ensureKeys', { purposes });
  }
  currentKey(purpose: NodeKeyPurpose): Promise<NodeKeyDescriptor> {
    return this.call('currentKey', { purpose });
  }
  getPublicKey(keyId: string): Promise<NodeKeyDescriptor> {
    return this.call('getPublicKey', { keyId });
  }
  async signEd25519(keyId: string, payload: Buffer): Promise<Buffer> {
    const result = await this.call<string>('signEd25519', { keyId, payload: payload.toString('base64url') });
    return Buffer.from(result, 'base64url');
  }
  async deriveX25519(keyId: string, peerPublicKey: string): Promise<Buffer> {
    const result = await this.call<string>('deriveX25519', { keyId, peerPublicKey });
    const shared = Buffer.from(result, 'base64url');
    if (shared.length !== 32 || shared.every(byte => byte === 0)) throw new Error('Invalid plugin X25519 result');
    return shared;
  }
  hpkeOpen<T>(keyId: string, envelope: HpkeEnvelope): Promise<T> {
    return this.call('hpkeOpen', { keyId, envelope });
  }
  rotate(purpose: NodeKeyPurpose, overlapMs = DEFAULT_KEY_OVERLAP_MS): Promise<NodeKeyDescriptor> {
    return this.call('rotate', { purpose, overlapMs });
  }

  private call<T>(method: string, params: object): Promise<T> {
    return new Promise((resolve, reject) => {
      const [command, ...args] = splitCommand(this.pluginCommand);
      if (!command) return reject(new Error('Invalid node crypto plugin command'));
      const child = spawn(command, args, { stdio: ['pipe', 'pipe', 'inherit'], shell: false });
      let output = Buffer.alloc(0);
      let settled = false;
      const finish = (error?: Error, value?: T) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        if (error) reject(error); else resolve(value as T);
      };
      const timer = setTimeout(() => {
        child.kill('SIGTERM');
        finish(new Error('Node crypto plugin timed out'));
      }, 10_000);
      child.stdout.on('data', (chunk: Buffer) => {
        if (output.length + chunk.length > MAX_PLUGIN_OUTPUT_BYTES) {
          child.kill('SIGTERM');
          finish(new Error('Node crypto plugin response too large'));
          return;
        }
        output = Buffer.concat([output, chunk]);
      });
      child.once('error', error => finish(error));
      child.once('close', code => {
        if (settled) return;
        if (code !== 0) return finish(new Error(`Node crypto plugin exited with code ${code}`));
        try {
          const parsed = JSON.parse(output.toString('utf8')) as { result?: T; error?: string };
          if (parsed.error) return finish(new Error(parsed.error));
          if (!Object.prototype.hasOwnProperty.call(parsed, 'result')) return finish(new Error('Invalid node crypto plugin response'));
          finish(undefined, parsed.result);
        } catch {
          finish(new Error('Invalid node crypto plugin JSON'));
        }
      });
      child.stdin.end(`${JSON.stringify({ method, ...params })}\n`);
    });
  }
}

export function createNodeCryptoBackend(config?: { backend?: 'local' | 'plugin'; pluginCommand?: string; keyDir?: string }): NodeCryptoBackend {
  const backend = config?.backend ?? (process.env.LATTICE_NODE_KEY_BACKEND === 'plugin' ? 'plugin' : 'local');
  if (backend === 'plugin') {
    return new PluginNodeCryptoBackend(config?.pluginCommand ?? process.env.LATTICE_NODE_KEY_PLUGIN_COMMAND ?? '');
  }
  return new LocalNodeCryptoBackend(config?.keyDir);
}

async function generateRecord(purpose: NodeKeyPurpose): Promise<LocalNodeKeyRecord> {
  const createdAt = new Date().toISOString();
  if (purpose === 'identity') {
    const pair = crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: { format: 'der', type: 'spki' },
      privateKeyEncoding: { format: 'der', type: 'pkcs8' },
    });
    const publicKey = Buffer.from(pair.publicKey).toString('base64');
    return {
      version: 1, purpose, algorithm: 'ed25519', publicKey,
      privateKey: Buffer.from(pair.privateKey).toString('base64'),
      keyId: publicKeyId(Buffer.from(pair.publicKey)), createdAt, status: 'active',
    };
  }
  if (purpose === 'onion') {
    const pair = generateRawX25519KeyPair();
    return {
      version: 1, purpose, algorithm: 'x25519-ntor', publicKey: pair.publicKey, privateKey: pair.privateKey,
      keyId: publicKeyId(Buffer.from(pair.publicKey, 'base64url')), createdAt, status: 'active',
    };
  }
  const pair = await generateHpkeKeyPair();
  return {
    version: 1, purpose, algorithm: 'x25519-hpke', publicKey: pair.publicKey, privateKey: pair.privateKey,
    keyId: pair.keyId, createdAt, status: 'active',
  };
}

function publicKeyId(publicKey: Buffer): string {
  return crypto.createHash('sha256').update(publicKey).digest('hex');
}

function publicDescriptor(record: LocalNodeKeyRecord): NodeKeyDescriptor {
  const { privateKey: _private, ...descriptor } = record;
  return descriptor;
}

function validateRecord(record: LocalNodeKeyRecord, expectedId: string): void {
  if (record.version !== 1 || record.keyId !== expectedId || !KEY_ID_RE.test(record.keyId)) throw new Error('Invalid node key record');
  if (!['identity', 'onion', 'gateway-encryption'].includes(record.purpose)) throw new Error('Invalid node key purpose');
  if (!['ed25519', 'x25519-ntor', 'x25519-hpke'].includes(record.algorithm)) throw new Error('Invalid node key algorithm');
  if (!record.publicKey || !record.privateKey || !Number.isFinite(new Date(record.createdAt).getTime())) throw new Error('Incomplete node key record');
  const publicBytes = record.algorithm === 'ed25519' ? Buffer.from(record.publicKey, 'base64') : Buffer.from(record.publicKey, 'base64url');
  if (publicKeyId(publicBytes) !== record.keyId) throw new Error('Node key record id mismatch');
  if (record.status !== 'active' && record.status !== 'retired') throw new Error('Invalid node key status');
}

function ensurePrivateDir(dir: string): void {
  fs.mkdirSync(dir, { recursive: true, mode: PRIVATE_DIR_MODE });
  fs.chmodSync(dir, PRIVATE_DIR_MODE);
}

function assertPrivateRegularFile(file: string): void {
  const stat = fs.statSync(file);
  if (!stat.isFile()) throw new Error(`Node key path is not a regular file: ${file}`);
  if ((stat.mode & 0o077) !== 0) throw new Error(`Node key file permissions must be 0600: ${file}`);
  if (stat.size < 2 || stat.size > 64 * 1024) throw new Error(`Invalid node key file size: ${file}`);
}

function writePrivateJsonAtomic(file: string, value: object): void {
  ensurePrivateDir(path.dirname(file));
  const temp = `${file}.tmp-${process.pid}-${crypto.randomBytes(4).toString('hex')}`;
  fs.writeFileSync(temp, JSON.stringify(value, null, 2), { mode: PRIVATE_FILE_MODE, flag: 'wx' });
  fs.renameSync(temp, file);
  fs.chmodSync(file, PRIVATE_FILE_MODE);
}

function splitCommand(command: string): string[] {
  const parts = command.trim().split(/\s+/).filter(Boolean);
  if (parts.some(part => /[;&|`$(){}<>]/.test(part))) throw new Error('Node crypto plugin command contains forbidden metacharacters');
  return parts;
}
