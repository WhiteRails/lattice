import { afterEach, describe, expect, it, vi } from 'vitest';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { LocalNodeCryptoBackend, PluginNodeCryptoBackend } from '../node/node-crypto';
import { generateRawX25519KeyPair } from '../node/onion-handshake';
import { sealHpkeJson } from '../node/hpke-envelope';

const dirs: string[] = [];

afterEach(() => {
  vi.useRealTimers();
  for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

function tempDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lattice-node-keys-'));
  dirs.push(dir);
  return dir;
}

describe('purpose-separated node crypto backend', () => {
  it('creates private 0600 records and performs only purpose-compatible operations', async () => {
    const dir = tempDir();
    const backend = new LocalNodeCryptoBackend(dir);
    const [identity, onion, gateway] = await backend.ensureKeys(['identity', 'onion', 'gateway-encryption']);
    expect(new Set([identity.keyId, onion.keyId, gateway.keyId]).size).toBe(3);

    for (const entry of fs.readdirSync(dir)) {
      const mode = fs.statSync(path.join(dir, entry)).mode & 0o777;
      expect(mode).toBe(0o600);
    }
    expect(fs.statSync(dir).mode & 0o777).toBe(0o700);

    const payload = Buffer.from('signed-control-message');
    const signature = await backend.signEd25519(identity.keyId, payload);
    const publicKey = crypto.createPublicKey({ key: Buffer.from(identity.publicKey, 'base64'), format: 'der', type: 'spki' });
    expect(crypto.verify(null, payload, publicKey, signature)).toBe(true);
    await expect(backend.signEd25519(onion.keyId, payload)).rejects.toThrow(/does not support/i);

    const peer = generateRawX25519KeyPair();
    await expect(backend.deriveX25519(onion.keyId, peer.publicKey)).resolves.toHaveLength(32);
    await expect(backend.deriveX25519(identity.keyId, peer.publicKey)).rejects.toThrow(/does not support/i);

    const now = Date.now();
    const envelope = await sealHpkeJson(gateway.publicKey, {
      direction: 'request', keyId: gateway.keyId, requestId: '11'.repeat(16), routeHash: `0x${'22'.repeat(32)}`,
      createdAt: new Date(now - 1_000).toISOString(), expiresAt: new Date(now + 60_000).toISOString(),
    }, { secret: 'gateway-only' });
    await expect(backend.hpkeOpen(gateway.keyId, envelope)).resolves.toEqual({ secret: 'gateway-only' });
  });

  it('rotates with an overlap while making the new key current', async () => {
    const backend = new LocalNodeCryptoBackend(tempDir());
    const oldKey = await backend.currentKey('onion');
    const next = await backend.rotate('onion', 60_000);
    expect(next.keyId).not.toBe(oldKey.keyId);
    expect((await backend.currentKey('onion')).keyId).toBe(next.keyId);
    expect((await backend.getPublicKey(oldKey.keyId)).status).toBe('retired');
    expect((await backend.getPublicKey(oldKey.keyId)).retireAfter).toBeTruthy();
  });

  it('opens HPKE with a retired key only during the configured overlap', async () => {
    vi.useFakeTimers();
    const now = new Date('2026-08-25T12:00:00.000Z').getTime();
    vi.setSystemTime(now);
    const backend = new LocalNodeCryptoBackend(tempDir());
    const oldKey = await backend.currentKey('gateway-encryption');
    const envelope = await sealHpkeJson(oldKey.publicKey, {
      direction: 'request', keyId: oldKey.keyId, requestId: '44'.repeat(16), routeHash: `0x${'55'.repeat(32)}`,
      createdAt: new Date(now).toISOString(), expiresAt: new Date(now + 120_000).toISOString(),
    }, { value: 'overlap' });
    await backend.rotate('gateway-encryption', 60_000);
    vi.setSystemTime(now + 30_000);
    await expect(backend.hpkeOpen(oldKey.keyId, envelope)).resolves.toEqual({ value: 'overlap' });
    vi.setSystemTime(now + 60_001);
    await expect(backend.hpkeOpen(oldKey.keyId, envelope)).rejects.toThrow(/overlap has expired/i);
  });

  it('bounds plugin output and never invokes a shell', async () => {
    const dir = tempDir();
    const script = path.join(dir, 'plugin.js');
    fs.writeFileSync(script, "process.stdin.resume(); process.stdout.write('x'.repeat(2097153));", { mode: 0o700 });
    const backend = new PluginNodeCryptoBackend(`${process.execPath} ${script}`);
    await expect(backend.currentKey('identity')).rejects.toThrow(/too large/i);
    await expect(new PluginNodeCryptoBackend('node; touch /tmp/nope').currentKey('identity')).rejects.toThrow(/metacharacters/i);
  });
});
