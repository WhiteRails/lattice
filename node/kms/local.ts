import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { LATTICE_DIR } from '../state';

export class LocalFileBackend {
  private keyDir: string;

  constructor(keyDir?: string) {
    this.keyDir = keyDir ?? path.join(LATTICE_DIR, 'keys');
  }

  get type() { return 'local' as const; }

  async getKey(keyId: string): Promise<string> {
    if (!/^[a-zA-Z0-9_-]+$/.test(keyId)) throw new Error(`Invalid keyId: ${keyId}`);
    const keyPath = path.join(this.keyDir, `${keyId}.key`);
    if (!fs.existsSync(keyPath)) throw new Error(`Key not found: ${keyId}`);
    const stats = fs.statSync(keyPath);
    if ((stats.mode & 0o077) !== 0) {
      console.warn(`[KMS] Warning: key file ${keyPath} has loose permissions (expected 0600)`);
    }
    return fs.readFileSync(keyPath, 'utf-8').trim();
  }

  async sign(keyId: string, payload: string): Promise<string> {
    const key = await this.getKey(keyId);
    // Ed25519 sign
    const keyObj = crypto.createPrivateKey({ key: Buffer.from(key, 'hex'), format: 'der', type: 'pkcs8' });
    const sig = crypto.sign(null, Buffer.from(payload), keyObj);
    return sig.toString('base64');
  }
}
