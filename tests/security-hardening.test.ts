import { afterEach, describe, expect, it, vi } from 'vitest';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { generateNodeKeyPair, deriveSessionKey, SessionManager } from '../node/session';
import { signOverlayMessage, parseOverlayMessage, stableStringify, type OverlayMessage } from '../node/message';
import { verifyIncomingOverlayFromPeer } from '../node/overlay-sign-key';
import { requestSignaturePayload, signData, verifySignature, generateKeyPair } from '../core/identity';

const homes: string[] = [];

afterEach(() => {
  for (const home of homes.splice(0)) fs.rmSync(home, { recursive: true, force: true });
  delete process.env.LATTICE_HOME;
  vi.resetModules();
});

function unsignedOverlay(): OverlayMessage {
  return {
    id: 'm1',
    type: 'request',
    source: 'bot1',
    destination: 'lp://echo.lattice',
    payload: { method: 'GET', url: '/ping', headers: {}, body: '' },
    trace: [],
    source_pubkey: generateNodeKeyPair().publicKey,
  };
}

describe('overlay hardening', () => {
  it('uses the shared secret in local mode, never a sender-selected ECDH key', () => {
    const receiver = generateNodeKeyPair();
    const attacker = generateNodeKeyPair();
    const forged = signOverlayMessage(
      { ...unsignedOverlay(), source_pubkey: attacker.publicKey },
      deriveSessionKey(receiver.privateKey, attacker.publicKey),
    );
    const manager = new SessionManager('receiver', receiver.privateKey);
    expect(verifyIncomingOverlayFromPeer({
      distributedMesh: false,
      mgr: manager,
      overlaySecret: 'operator-secret',
      expectedPeerPubKeyB64: attacker.publicKey,
      msg: forged,
    })).toBe(false);
  });

  it('rejects malformed and over-nested overlay frames before authentication', () => {
    expect(parseOverlayMessage('null')).toBeNull();
    expect(parseOverlayMessage(JSON.stringify({ ...unsignedOverlay(), trace: [], unexpected: true }))).toBeNull();
    expect(parseOverlayMessage(JSON.stringify({ ...unsignedOverlay(), source_pubkey: 'AAAA' }))).toBeNull();

    let deeplyNested: unknown = null;
    for (let i = 0; i < 40; i++) deeplyNested = [deeplyNested];
    expect(() => stableStringify(deeplyNested)).toThrow(/maximum depth/i);
  });
});

describe('local principal hardening', () => {
  it('rejects path-equivalent agent and policy names before filesystem access', async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lat-security-'));
    homes.push(home);
    process.env.LATTICE_HOME = home;
    vi.resetModules();
    const { initDirs, saveAgent, saveRevocation, loadAgent, isRevoked } = await import('../node/state');
    const { PolicyLoader } = await import('../node/policy-loader');
    initDirs();
    saveAgent('bot1', {
      cert: {}, publicKey: 'public', privateKey: 'private', createdAt: new Date().toISOString(),
    });
    saveRevocation('bot1');

    expect(() => loadAgent('./bot1')).toThrow(/invalid agent name/i);
    expect(isRevoked('./bot1')).toBe(true);
    expect(() => new PolicyLoader().load('../bot1')).toThrow(/invalid agent name/i);
  });

  it('cryptographically binds an agent name to each request', () => {
    const keys = generateKeyPair();
    const payload = requestSignaturePayload({
      agent: 'bot1', method: 'POST', host: 'echo.lattice', url: '/write', timestamp: '2026-01-01T00:00:00.000Z', bodyHash: 'a'.repeat(64),
    });
    const signature = signData(payload, keys.privateKey);
    const swappedAgent = requestSignaturePayload({
      agent: 'admin', method: 'POST', host: 'echo.lattice', url: '/write', timestamp: '2026-01-01T00:00:00.000Z', bodyHash: 'a'.repeat(64),
    });
    expect(verifySignature(payload, signature, keys.publicKey)).toBe(true);
    expect(verifySignature(swappedAgent, signature, keys.publicKey)).toBe(false);
  });
});

describe('self-auth routing hardening', () => {
  it('does not obtain .id endpoint metadata from federation', async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lat-security-'));
    homes.push(home);
    process.env.LATTICE_HOME = home;
    vi.resetModules();
    const { initDirs, saveCA } = await import('../node/state');
    const { LatticeCA } = await import('../core/ca');
    initDirs();
    const ca = new LatticeCA('ca.test');
    saveCA({
      caId: ca.id, publicKey: ca.publicKey, privateKey: ca.privateKey,
      overlaySecret: crypto.randomBytes(32).toString('base64'), createdAt: new Date().toISOString(),
    });
    const { LpGatewayResolver, LpRoutingNotFoundError } = await import('../node/lp-resolver');
    const id = Buffer.from(generateNodeKeyPair().publicKey, 'base64').toString('hex') + '.id';
    const resolver = new LpGatewayResolver({ registry: { federationUrls: ['http://127.0.0.1:1'] } } as any, null);
    await expect(resolver.resolveDestination(`lp://${id}`)).rejects.toBeInstanceOf(LpRoutingNotFoundError);
  });
});
