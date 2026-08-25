import { afterEach, describe, expect, it, vi } from 'vitest';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { WebSocket, WebSocketServer } from 'ws';
import { LatticeCA } from '../core/ca';
import { generateKeyPair, hashRequestBody, requestSignaturePayload, signData } from '../core/identity';
import { signOverlayMessage, type OverlayMessage } from '../node/message';

const homes: string[] = [];
const closers: Array<() => Promise<void> | void> = [];

afterEach(async () => {
  while (closers.length) await closers.pop()!();
  for (const home of homes.splice(0)) fs.rmSync(home, { recursive: true, force: true });
  delete process.env.LATTICE_HOME;
  vi.resetModules();
});

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = http.createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      server.close(() => typeof address === 'object' && address ? resolve(address.port) : reject(new Error('missing port')));
    });
  });
}

async function waitUntil(predicate: () => boolean, timeoutMs = 2_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!predicate()) {
    if (Date.now() >= deadline) throw new Error('condition did not become true before timeout');
    await new Promise(resolve => setTimeout(resolve, 10));
  }
}

async function setupHome(): Promise<void> {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lat-replica-'));
  homes.push(home);
  process.env.LATTICE_HOME = home;
  vi.resetModules();
  const { initDirs, saveCA } = await import('../node/state');
  initDirs();
  const keys = generateKeyPair();
  saveCA({
    caId: 'ca.test', publicKey: keys.publicKey, privateKey: keys.privateKey,
    overlaySecret: crypto.randomBytes(32).toString('base64'), createdAt: new Date().toISOString(),
  });
}

function signedHeaders(agent: string, privateKey: string, timestamp: string, nonce: string, certificate?: unknown): Record<string, string> {
  const body = Buffer.alloc(0);
  const signature = signData(requestSignaturePayload({
    agent, method: 'GET', host: 'echo.lattice', url: '/ping', timestamp, bodyHash: hashRequestBody(body),
  }), privateKey);
  return {
    host: 'echo.lattice',
    'x-lattice-agent': agent,
    'x-lattice-signature': signature,
    'x-lattice-timestamp': timestamp,
    'x-lattice-nonce': nonce,
    ...(certificate ? { 'x-lattice-agent-certificate': Buffer.from(JSON.stringify(certificate), 'utf8').toString('base64url') } : {}),
  };
}

async function httpGet(port: number, headers: Record<string, string>): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const request = http.request({ host: '127.0.0.1', port, path: '/ping', method: 'GET', headers }, response => {
      const chunks: Buffer[] = [];
      response.on('data', data => chunks.push(Buffer.from(data)));
      response.on('end', () => resolve({ status: response.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }));
    });
    request.once('error', reject);
    request.end();
  });
}

async function wsRequest(url: string, message: OverlayMessage): Promise<OverlayMessage> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    const timer = setTimeout(() => { ws.close(); reject(new Error('websocket response timeout')); }, 5_000);
    ws.once('open', () => ws.send(JSON.stringify(message)));
    ws.once('message', raw => {
      clearTimeout(timer);
      ws.close();
      resolve(JSON.parse(raw.toString()) as OverlayMessage);
    });
    ws.once('error', error => { clearTimeout(timer); reject(error); });
  });
}

describe('replica replay contracts', () => {
  it('admits a signed request through only one of two Entry replicas', async () => {
    await setupHome();
    const { saveAgent, getOrCreateOverlayKeyPair, loadCA } = await import('../node/state');
    const { EntryNode } = await import('../node/entry');
    const { LocalReplayStore } = await import('../node/replay-store');
    const agent = generateKeyPair();
    saveAgent('bot1', { cert: {}, publicKey: agent.publicKey, privateKey: agent.privateKey, createdAt: new Date().toISOString() });
    const [relayPort, firstPort, secondPort] = await Promise.all([freePort(), freePort(), freePort()]);
    const secret = loadCA().overlaySecret;
    const relayKey = getOrCreateOverlayKeyPair().publicKey;
    const relay = new WebSocketServer({ port: relayPort, host: '127.0.0.1' });
    relay.on('connection', ws => ws.on('message', raw => {
      const request = JSON.parse(raw.toString()) as OverlayMessage;
      ws.send(JSON.stringify(signOverlayMessage({
        id: request.id, type: 'response', source: 'relay', destination: request.source,
        payload: { status: 200, headers: { 'content-type': 'text/plain' }, body: Buffer.from('ok').toString('base64') },
        trace: request.trace, source_pubkey: relayKey, source_node_role: 'relay',
      }, secret)));
    }));
    closers.push(() => new Promise(resolve => relay.close(() => resolve())));

    const sharedReplay = new LocalReplayStore();
    const first = new EntryNode({ port: firstPort, relayUrls: [`ws://127.0.0.1:${relayPort}`], replayStore: sharedReplay });
    const second = new EntryNode({ port: secondPort, relayUrls: [`ws://127.0.0.1:${relayPort}`], replayStore: sharedReplay });
    closers.push(() => first.close(), () => second.close());
    await new Promise(resolve => setTimeout(resolve, 30));

    const headers = signedHeaders('bot1', agent.privateKey, new Date().toISOString(), 'replica-entry-0001');
    const results = await Promise.all([httpGet(firstPort, headers), httpGet(secondPort, headers)]);
    expect(results.map(result => result.status).sort()).toEqual([200, 401]);
    expect(results.filter(result => result.status === 200)[0]?.body).toBe('ok');
  });

  it('admits a signed action through only one of two Gateway replicas', async () => {
    await setupHome();
    const { getOrCreateOverlayKeyPair, loadCA } = await import('../node/state');
    const { ServiceGateway } = await import('../node/gateway');
    const { PolicyLoader } = await import('../node/policy-loader');
    const { LocalReplayStore } = await import('../node/replay-store');
    const agent = generateKeyPair();
    const policy = new PolicyLoader();
    policy.grant('bot1', 'lp://echo.lattice', ['ping']);
    policy.pinAgentPublicKey('bot1', agent.publicKey);
    const [backendPort, firstPort, secondPort] = await Promise.all([freePort(), freePort(), freePort()]);
    let backendCalls = 0;
    const backend = http.createServer((_request, response) => {
      backendCalls++;
      response.writeHead(200, { 'content-type': 'text/plain' });
      response.end('pong');
    });
    await new Promise<void>((resolve, reject) => {
      backend.once('error', reject);
      backend.listen(backendPort, '127.0.0.1', () => resolve());
    });
    closers.push(() => new Promise(resolve => backend.close(() => resolve())));

    const sharedReplay = new LocalReplayStore();
    const first = new ServiceGateway('lp://echo.lattice', `http://127.0.0.1:${backendPort}`, { port: firstPort, replayStore: sharedReplay });
    const second = new ServiceGateway('lp://echo.lattice', `http://127.0.0.1:${backendPort}`, { port: secondPort, replayStore: sharedReplay });
    closers.push(() => first.close(), () => second.close());
    await new Promise(resolve => setTimeout(resolve, 30));

    const timestamp = new Date().toISOString();
    const nonce = 'replica-gateway-0001';
    const body = Buffer.alloc(0);
    const proofSignature = signData(requestSignaturePayload({
      agent: 'bot1', method: 'GET', host: 'echo.lattice', url: '/ping', timestamp, bodyHash: hashRequestBody(body),
    }), agent.privateKey);
    const relayKey = getOrCreateOverlayKeyPair().publicKey;
    const message = signOverlayMessage({
      id: 'replica-gateway-request', type: 'request', source: 'bot1', destination: 'lp://echo.lattice',
      payload: {
        method: 'GET', url: '/ping', headers: { host: 'echo.lattice' }, body: '',
        agent_proof: { agent: 'bot1', public_key: agent.publicKey, signature: proofSignature, timestamp, nonce, body_hash: hashRequestBody(body), host: 'echo.lattice' },
      },
      trace: ['entry', 'relay'], source_pubkey: relayKey, source_node_role: 'relay',
    }, loadCA().overlaySecret);
    const responses = await Promise.all([
      wsRequest(`ws://127.0.0.1:${firstPort}`, message),
      wsRequest(`ws://127.0.0.1:${secondPort}`, message),
    ]);
    expect(responses.map(response => response.payload.status).sort()).toEqual([200, 401]);
    expect(backendCalls).toBe(1);
  });

  it('carries a trusted portable issuer certificate across Entry, Relay, and Gateway', async () => {
    await setupHome();
    const { getOrCreateOverlayKeyPair } = await import('../node/state');
    const { EntryNode } = await import('../node/entry');
    const { RelayNode } = await import('../node/relay');
    const { ServiceGateway } = await import('../node/gateway');
    const { upsertRoutingPayload, ROUTING_PAYLOAD_VERSION } = await import('../node/routing-cache');
    const issuer = new LatticeCA('agents.example');
    const agent = generateKeyPair();
    const signed = issuer.issueAgentCert({
      agent_id: 'agent:agents.example:remote', owner_org: 'example', agent_type: 'autonomous', version: '1',
      public_key: agent.publicKey, allowed_capability_classes: ['lp://echo.lattice:ping'], forbidden_capability_classes: [], expires_in_days: 1,
    });
    const [backendPort, relayPort, gatewayPort, entryPort] = await Promise.all([
      freePort(), freePort(), freePort(), freePort(),
    ]);
    let backendCalls = 0;
    const backend = http.createServer((_request, response) => {
      backendCalls++;
      response.writeHead(200, { 'content-type': 'text/plain' });
      response.end('portable-ok');
    });
    await new Promise<void>((resolve, reject) => {
      backend.once('error', reject);
      backend.listen(backendPort, '127.0.0.1', () => resolve());
    });
    closers.push(() => new Promise(resolve => backend.close(() => resolve())));

    upsertRoutingPayload(null, {
      version: ROUTING_PAYLOAD_VERSION,
      fqdn: 'echo.lattice',
      gatewayPubKeyB64: getOrCreateOverlayKeyPair().publicKey,
      gatewayEndpoints: [`ws://127.0.0.1:${gatewayPort}`],
    });
    const gateway = new ServiceGateway('lp://echo.lattice', `http://127.0.0.1:${backendPort}`, {
      port: gatewayPort,
      nodeConfig: { gateway: { issuerGrants: [{
        issuer_id: issuer.id, public_key: issuer.publicKey,
        services: [{ address: 'lp://echo.lattice', actions: ['ping'] }],
      }] } } as any,
    });
    const relay = new RelayNode({ port: relayPort });
    const entry = new EntryNode({
      port: entryPort,
      relayUrls: [`ws://127.0.0.1:${relayPort}`],
      nodeConfig: { agentTrust: { issuers: [{ issuer_id: issuer.id, public_key: issuer.publicKey }] } } as any,
    });
    closers.push(() => entry.close(), () => gateway.close(), () => relay.close());
    await new Promise(resolve => setTimeout(resolve, 40));

    const result = await httpGet(entryPort, signedHeaders(
      'remote', agent.privateKey, new Date().toISOString(), 'portable-e2e-0001', signed,
    ));
    expect(result).toEqual({ status: 200, body: 'portable-ok' });
    expect(backendCalls).toBe(1);

    const restrictedAgent = generateKeyPair();
    const restricted = issuer.issueAgentCert({
      agent_id: 'agent:agents.example:restricted', owner_org: 'example', agent_type: 'autonomous', version: '1',
      public_key: restrictedAgent.publicKey, allowed_capability_classes: [], forbidden_capability_classes: [], expires_in_days: 1,
    });
    const denied = await httpGet(entryPort, signedHeaders(
      'restricted', restrictedAgent.privateKey, new Date().toISOString(), 'portable-e2e-0002', restricted,
    ));
    expect(denied.status).toBe(401);
    expect(backendCalls).toBe(1);
  });

  it('fails over from a preferred unavailable Gateway endpoint to a live replica', async () => {
    await setupHome();
    const { getOrCreateOverlayKeyPair, loadCA } = await import('../node/state');
    const { ServiceGateway } = await import('../node/gateway');
    const { RelayNode } = await import('../node/relay');
    const { PolicyLoader } = await import('../node/policy-loader');
    const { upsertRoutingPayload, ROUTING_PAYLOAD_VERSION } = await import('../node/routing-cache');
    const { rendezvousOrder } = await import('../node/rendezvous');
    const agent = generateKeyPair();
    const [backendPort, relayPort, liveGatewayPort, unavailableGatewayPort] = await Promise.all([
      freePort(), freePort(), freePort(), freePort(),
    ]);
    const unavailable = `ws://127.0.0.1:${unavailableGatewayPort}`;
    const live = `ws://127.0.0.1:${liveGatewayPort}`;
    const agentName = Array.from({ length: 100 }, (_, index) => `bot${index}`).find(name =>
      rendezvousOrder([unavailable, live], `echo.lattice\0${name}`)[0] === unavailable,
    );
    expect(agentName).toBeDefined();
    const policy = new PolicyLoader();
    policy.grant(agentName!, 'lp://echo.lattice', ['ping']);
    policy.pinAgentPublicKey(agentName!, agent.publicKey);
    const nodeKey = getOrCreateOverlayKeyPair().publicKey;
    upsertRoutingPayload(null, {
      version: ROUTING_PAYLOAD_VERSION,
      fqdn: 'echo.lattice', gatewayPubKeyB64: nodeKey,
      gatewayEndpoints: [unavailable, live],
    });
    const backend = http.createServer((_request, response) => {
      response.writeHead(200, { 'content-type': 'text/plain' });
      response.end('failover-ok');
    });
    await new Promise<void>((resolve, reject) => {
      backend.once('error', reject);
      backend.listen(backendPort, '127.0.0.1', () => resolve());
    });
    closers.push(() => new Promise(resolve => backend.close(() => resolve())));
    const gateway = new ServiceGateway('lp://echo.lattice', `http://127.0.0.1:${backendPort}`, { port: liveGatewayPort });
    const relay = new RelayNode({ port: relayPort });
    closers.push(() => gateway.close(), () => relay.close());
    await new Promise(resolve => setTimeout(resolve, 40));

    const timestamp = new Date().toISOString();
    const nonce = 'relay-failover-0001';
    const body = Buffer.alloc(0);
    const proofSignature = signData(requestSignaturePayload({
      agent: agentName!, method: 'GET', host: 'echo.lattice', url: '/ping', timestamp, bodyHash: hashRequestBody(body),
    }), agent.privateKey);
    const request = signOverlayMessage({
      id: 'relay-failover-request', type: 'request', source: agentName!, destination: 'lp://echo.lattice',
      payload: {
        method: 'GET', url: '/ping', headers: { host: 'echo.lattice' }, body: '',
        agent_proof: { agent: agentName!, public_key: agent.publicKey, signature: proofSignature, timestamp, nonce, body_hash: hashRequestBody(body), host: 'echo.lattice' },
      }, trace: ['entry'], source_pubkey: nodeKey, source_node_role: 'entry',
    }, loadCA().overlaySecret);
    const response = await wsRequest(`ws://127.0.0.1:${relayPort}`, request);
    expect(response.payload.status).toBe(200);
    expect(Buffer.from(response.payload.body ?? '', 'base64').toString('utf8')).toBe('failover-ok');
  });

  it('multiplexes concurrent requests through one hidden Gateway without adding request listeners', async () => {
    await setupHome();
    const { getOrCreateOverlayKeyPair, saveAgent } = await import('../node/state');
    const { EntryNode } = await import('../node/entry');
    const { RelayNode } = await import('../node/relay');
    const { ServiceGateway } = await import('../node/gateway');
    const { PolicyLoader } = await import('../node/policy-loader');
    const { upsertRoutingPayload, ROUTING_PAYLOAD_VERSION } = await import('../node/routing-cache');
    const agent = generateKeyPair();
    const [backendPort, relayPort, entryPort] = await Promise.all([freePort(), freePort(), freePort()]);
    let backendCalls = 0;
    const backend = http.createServer((_request, response) => {
      backendCalls++;
      response.writeHead(200, { 'content-type': 'text/plain' });
      response.end('hidden-ok');
    });
    await new Promise<void>((resolve, reject) => {
      backend.once('error', reject);
      backend.listen(backendPort, '127.0.0.1', () => resolve());
    });
    closers.push(() => new Promise(resolve => backend.close(() => resolve())));

    const policy = new PolicyLoader();
    saveAgent('bot1', { cert: {}, publicKey: agent.publicKey, privateKey: agent.privateKey, createdAt: new Date().toISOString() });
    policy.grant('bot1', 'lp://echo.lattice', ['ping']);
    policy.pinAgentPublicKey('bot1', agent.publicKey);
    upsertRoutingPayload(null, {
      version: ROUTING_PAYLOAD_VERSION,
      fqdn: 'echo.lattice',
      gatewayPubKeyB64: getOrCreateOverlayKeyPair().publicKey,
      gatewayEndpoints: [],
    });
    const relay = new RelayNode({ port: relayPort });
    const gateway = new ServiceGateway('lp://echo.lattice', `http://127.0.0.1:${backendPort}`, {
      nodeConfig: {
        gateway: {
          mode: 'hidden',
          hiddenServiceAddress: 'lp://echo.lattice',
          rendezvousRelays: [`ws://127.0.0.1:${relayPort}`],
        },
      } as any,
    });
    const entry = new EntryNode({ port: entryPort, relayUrls: [`ws://127.0.0.1:${relayPort}`] });
    closers.push(() => entry.close(), () => gateway.close(), () => relay.close());
    await waitUntil(() => Boolean((relay as any).hiddenGateways.get('echo.lattice')));
    const hidden = (relay as any).hiddenGateways.get('echo.lattice');
    const listenersBefore = hidden.ws.listenerCount('message');

    const timestamp = new Date().toISOString();
    const responses = await Promise.all(Array.from({ length: 32 }, (_, index) =>
      httpGet(entryPort, signedHeaders('bot1', agent.privateKey, timestamp, `hidden-mux-${index}`)),
    ));
    expect(responses.every(response => response.status === 200 && response.body === 'hidden-ok')).toBe(true);
    expect(backendCalls).toBe(32);
    expect(hidden.ws.listenerCount('message')).toBe(listenersBefore);
  });
});
