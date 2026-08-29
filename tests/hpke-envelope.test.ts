import { describe, expect, it } from 'vitest';
import {
  generateHpkeKeyPair,
  hpkeKeyId,
  openHpkeJson,
  sealHpkeJson,
  type HpkeEnvelope,
} from '../node/hpke-envelope';

function header(keyId: string) {
  const now = Date.now();
  return {
    direction: 'request' as const,
    keyId,
    requestId: 'ab'.repeat(16),
    routeHash: `0x${'cd'.repeat(32)}`,
    createdAt: new Date(now - 1_000).toISOString(),
    expiresAt: new Date(now + 60_000).toISOString(),
  };
}

describe('Lattice HPKE envelopes', () => {
  it('encrypts canonical JSON to a gateway and rejects the wrong key', async () => {
    const recipient = await generateHpkeKeyPair();
    const wrong = await generateHpkeKeyPair();
    expect(recipient.keyId).toBe(hpkeKeyId(recipient.publicKey));
    const envelope = await sealHpkeJson(recipient.publicKey, header(recipient.keyId), {
      agent: 'private-bot', body: 'private-body', nested: { ok: true },
    });

    expect(JSON.stringify(envelope)).not.toContain('private-bot');
    expect(JSON.stringify(envelope)).not.toContain('private-body');
    await expect(openHpkeJson(recipient.privateKey, envelope)).resolves.toEqual({
      agent: 'private-bot', body: 'private-body', nested: { ok: true },
    });
    await expect(openHpkeJson(wrong.privateKey, envelope)).rejects.toThrow();
  });

  it('binds metadata as AAD and fails closed on ciphertext tampering', async () => {
    const recipient = await generateHpkeKeyPair();
    const envelope = await sealHpkeJson(recipient.publicKey, header(recipient.keyId), { ok: true });
    const changedRoute: HpkeEnvelope = { ...envelope, route_hash: `0x${'ef'.repeat(32)}` };
    await expect(openHpkeJson(recipient.privateKey, changedRoute)).rejects.toThrow();

    const bytes = Buffer.from(envelope.ciphertext, 'base64url');
    bytes[0] ^= 1;
    await expect(openHpkeJson(recipient.privateKey, { ...envelope, ciphertext: bytes.toString('base64url') })).rejects.toThrow();
  });

  it('rejects expired envelopes and excessive validity windows', async () => {
    const recipient = await generateHpkeKeyPair();
    const old = Date.now() - 10 * 60_000;
    const expired = await sealHpkeJson(recipient.publicKey, {
      ...header(recipient.keyId),
      createdAt: new Date(old).toISOString(),
      expiresAt: new Date(old + 60_000).toISOString(),
    }, { ok: true });
    await expect(openHpkeJson(recipient.privateKey, expired)).rejects.toThrow(/expired/i);

    const now = Date.now();
    await expect(sealHpkeJson(recipient.publicKey, {
      ...header(recipient.keyId),
      createdAt: new Date(now).toISOString(),
      expiresAt: new Date(now + 10 * 60_000).toISOString(),
    }, { ok: true })).rejects.toThrow(/five minutes/i);
  });
});
