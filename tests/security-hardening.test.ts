import { afterEach, describe, expect, it, vi } from 'vitest';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as http from 'http';
import { WebSocketServer } from 'ws';
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

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = http.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      server.close(() => typeof address === 'object' && address ? resolve(address.port) : reject(new Error('no port')));
    });
  });
}

async function postStatus(port: number, body: Buffer): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1', port, method: 'POST', path: '/write',
      headers: { host: 'echo.lattice', 'x-lattice-agent': 'bot1', 'content-length': body.length },
    }, res => {
      res.resume();
      res.once('end', () => resolve(res.statusCode ?? 0));
    });
    req.once('error', reject);
    req.end(body);
  });
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

  it('uses the registry-bound peer key in mesh mode, never the key claimed by a frame', () => {
    const receiver = generateNodeKeyPair();
    const trustedPeer = generateNodeKeyPair();
    const attacker = generateNodeKeyPair();
    const forged = signOverlayMessage(
      { ...unsignedOverlay(), source_pubkey: attacker.publicKey },
      deriveSessionKey(receiver.privateKey, attacker.publicKey),
    );
    const manager = new SessionManager('receiver', receiver.privateKey);
    expect(verifyIncomingOverlayFromPeer({
      distributedMesh: true,
      mgr: manager,
      overlaySecret: 'unused-in-mesh',
      expectedPeerPubKeyB64: trustedPeer.publicKey,
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

describe('backend forwarding hardening', () => {
  it('rebuilds backend requests without caller-controlled framing or hop-by-hop headers', async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lat-security-'));
    homes.push(home);
    process.env.LATTICE_HOME = home;
    vi.resetModules();
    const { initDirs, saveCA } = await import('../node/state');
    const { LatticeCA } = await import('../core/ca');
    initDirs();
    const ca = new LatticeCA('ca.test');
    saveCA({
      caId: ca.id,
      publicKey: ca.publicKey,
      privateKey: ca.privateKey,
      overlaySecret: crypto.randomBytes(32).toString('base64'),
      createdAt: new Date().toISOString(),
    });
    const { ServiceGateway, actionIdForProof } = await import('../node/gateway');
    const gateway = new ServiceGateway('lp://echo.lattice', 'http://127.0.0.1:9001', {
      port: 0,
      nodeConfig: null,
    });
    try {
      const body = Buffer.from('canonical body');
      const proof = {
        agent: 'bot1', public_key: 'pinned-public-key', signature: 'signed-action', timestamp: '2026-01-01T00:00:00.000Z',
        nonce: 'nonce-12345678', body_hash: 'a'.repeat(64), host: 'echo.lattice',
      };
      const actionId = actionIdForProof(proof);
      const result = (gateway as any).buildBackendRequest({
        ...unsignedOverlay(),
        payload: {
          method: 'POST',
          url: '/write?ok=1',
          body: body.toString('base64'),
          headers: {
            host: 'attacker.invalid',
            connection: 'keep-alive',
            'transfer-encoding': 'chunked',
            'content-length': '999999',
            'x-lattice-signature': 'do-not-forward',
            'x-safe': 'kept',
          },
        },
      }, actionId);
      expect(result).not.toBeNull();
      expect(result.options.method).toBe('POST');
      expect(result.options.path).toBe('/write?ok=1');
      expect(result.options.headers).toMatchObject({
        host: '127.0.0.1:9001',
        'content-length': String(body.length),
        'x-lattice-action-id': actionId,
        'x-safe': 'kept',
      });
      expect(result.options.headers).not.toHaveProperty('connection');
      expect(result.options.headers).not.toHaveProperty('transfer-encoding');
      expect(result.options.headers).not.toHaveProperty('x-lattice-signature');
      expect((gateway as any).buildBackendRequest({
        ...unsignedOverlay(), payload: { method: 'TRACE', url: '/', body: '' },
      })).toBeNull();
      expect((gateway as any).buildBackendRequest({
        ...unsignedOverlay(), payload: { method: 'GET', url: '//attacker.invalid/', body: '' },
      })).toBeNull();
    } finally {
      gateway.close();
    }
  });

  it('derives the same cross-replica idempotency key only for the same signed proof', async () => {
    const { actionIdForProof } = await import('../node/gateway');
    const proof = {
      agent: 'bot1', public_key: 'public-key', signature: 'signature-a', timestamp: '2026-01-01T00:00:00.000Z',
      nonce: 'nonce-12345678', body_hash: 'a'.repeat(64), host: 'echo.lattice',
    };
    expect(actionIdForProof(proof)).toBe(actionIdForProof({ ...proof }));
    expect(actionIdForProof(proof)).not.toBe(actionIdForProof({ ...proof, signature: 'signature-b' }));
  });

  it('bounds a backend response before it can exceed the overlay frame budget', async () => {
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
    const backendPort = await freePort();
    const backend = http.createServer((_request, response) => {
      response.writeHead(200, { 'content-type': 'application/octet-stream' });
      response.end(Buffer.alloc(512 * 1024 + 1));
    });
    await new Promise<void>((resolve, reject) => backend.listen(backendPort, '127.0.0.1', resolve).once('error', reject));
    const { ServiceGateway } = await import('../node/gateway');
    const gateway = new ServiceGateway('lp://echo.lattice', `http://127.0.0.1:${backendPort}`, { port: 0, nodeConfig: null });
    try {
      const rawResponse = await new Promise<string>((resolve, reject) => {
        const fakeWs = { readyState: 1, send: (frame: string) => resolve(frame) } as any;
        (gateway as any).forwardHttp({
          ...unsignedOverlay(),
          id: 'oversized-backend-response',
          payload: { method: 'GET', url: '/large', headers: {}, body: '' },
        }, fakeWs);
        setTimeout(() => reject(new Error('backend response bound timed out')), 2_000).unref();
      });
      const response = parseOverlayMessage(rawResponse);
      expect(response?.payload.status).toBe(502);
      expect(Buffer.from(response?.payload.body ?? '', 'base64').toString('utf8')).toMatch(/too large/i);
    } finally {
      gateway.close();
      await new Promise<void>(resolve => backend.close(() => resolve()));
    }
  });

  it('keeps a Gateway request pending until its backend has settled', async () => {
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
    const backendPort = await freePort();
    let markBackendReached: (() => void) | undefined;
    const backendReached = new Promise<void>(resolve => { markBackendReached = resolve; });
    let releaseBackend: (() => void) | undefined;
    const waitForRelease = new Promise<void>(resolve => { releaseBackend = resolve; });
    const backend = http.createServer(async (_request, response) => {
      markBackendReached!();
      await waitForRelease;
      response.writeHead(200, { 'content-type': 'text/plain' });
      response.end('ok');
    });
    await new Promise<void>((resolve, reject) => backend.listen(backendPort, '127.0.0.1', resolve).once('error', reject));
    const { ServiceGateway, backendMaxSocketsFromEnv } = await import('../node/gateway');
    expect(backendMaxSocketsFromEnv({ LATTICE_BACKEND_MAX_SOCKETS: '128' })).toBe(128);
    expect(() => backendMaxSocketsFromEnv({ LATTICE_BACKEND_MAX_SOCKETS: 'unbounded' })).toThrow(/integer/i);
    const gateway = new ServiceGateway('lp://echo.lattice', `http://127.0.0.1:${backendPort}`, { port: 0, nodeConfig: null });
    try {
      const pending = (gateway as any).forwardHttp({
        ...unsignedOverlay(),
        id: 'slow-backend-response',
        payload: { method: 'GET', url: '/slow', headers: {}, body: '' },
      }, { readyState: 3 } as any);
      let completed = false;
      void pending.then(() => { completed = true; });
      await backendReached;
      expect(completed).toBe(false);
      releaseBackend!();
      await pending;
      expect(completed).toBe(true);
    } finally {
      gateway.close();
      await new Promise<void>(resolve => backend.close(() => resolve()));
    }
  });
});

describe('Entry ingress bounds', () => {
  it('rejects an agent body before it can expand beyond the overlay frame budget', async () => {
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
    const { EntryNode } = await import('../node/entry');
    const port = await freePort();
    const entry = new EntryNode({ port, nodeConfig: null, relayUrls: ['ws://127.0.0.1:1'] });
    try {
      await new Promise(resolve => setTimeout(resolve, 20));
      expect(await postStatus(port, Buffer.alloc(512 * 1024 + 1))).toBe(413);
    } finally {
      entry.close();
    }
  });
});

describe('Gateway lifecycle bounds', () => {
  it('does not reconnect a hidden rendezvous socket after the replica is closed', async () => {
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
    const relayPort = await freePort();
    let connections = 0;
    let firstConnection!: () => void;
    const connected = new Promise<void>(resolve => { firstConnection = resolve; });
    const relay = new WebSocketServer({ port: relayPort, host: '127.0.0.1' });
    relay.on('connection', ws => { connections++; firstConnection(); ws.close(); });
    await new Promise<void>((resolve, reject) => {
      relay.once('listening', resolve);
      relay.once('error', reject);
    });
    const { ServiceGateway } = await import('../node/gateway');
    const gateway = new ServiceGateway('lp://echo.lattice', 'http://127.0.0.1:9001', {
      nodeConfig: {
        gateway: {
          mode: 'hidden', hiddenServiceAddress: 'lp://echo.lattice',
          rendezvousRelays: [`ws://127.0.0.1:${relayPort}`],
        },
      } as any,
    });
    try {
      await connected;
      gateway.close();
      await new Promise(resolve => setTimeout(resolve, 1_100));
      expect(connections).toBe(1);
    } finally {
      gateway.close();
      await new Promise<void>(resolve => relay.close(() => resolve()));
    }
  });
});
