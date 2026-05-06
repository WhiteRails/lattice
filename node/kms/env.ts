export class EnvBackend {
  get type() { return 'env' as const; }

  async getKey(keyId: string): Promise<string> {
    const envVar = `LATTICE_KEY_${keyId.toUpperCase().replace(/-/g, '_')}`;
    const key = process.env[envVar];
    if (!key) throw new Error(`Key not found in environment: ${envVar}`);
    console.warn(`[KMS] EnvBackend: reading key from env var. Consider using local file or hardware KMS for production.`);
    return key;
  }

  async sign(keyId: string, payload: string): Promise<string> {
    const key = await this.getKey(keyId);
    const crypto = require('crypto');
    const keyObj = crypto.createPrivateKey({ key: Buffer.from(key, 'hex'), format: 'der', type: 'pkcs8' });
    const sig = crypto.sign(null, Buffer.from(payload), keyObj);
    return sig.toString('base64');
  }
}
