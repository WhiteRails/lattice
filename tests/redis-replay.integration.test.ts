import { afterEach, describe, expect, it, vi } from 'vitest';
import * as net from 'net';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as crypto from 'crypto';
import * as http from 'http';
import { spawn, type ChildProcess } from 'child_process';
import { WebSocket, WebSocketServer } from 'ws';
import { RedisReplayStore } from '../node/replay-store';
import { generateKeyPair, hashRequestBody, requestSignaturePayload, signData } from '../core/identity';
import { signOverlayMessage, type OverlayMessage } from '../node/message';
import { LatticeCA } from '../core/ca';
import { generateNodeKeyPair } from '../node/session';

const enabled = process.env.LATTICE_REDIS_INTEGRATION === '1';
let server: ChildProcess | undefined;
const homes: string[] = [];

afterEach(async () => {
  if (server && server.exitCode === null && server.signalCode === null) {
    await new Promise<void>(resolve => {
      server!.once('exit', () => resolve());
      server!.kill('SIGTERM');
    });
  }
  server = undefined;
  for (const home of homes.splice(0)) fs.rmSync(home, { recursive: true, force: true });
  delete process.env.LATTICE_HOME;
});

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const probe = net.createServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const address = probe.address();
      probe.close(() => typeof address === 'object' && address ? resolve(address.port) : reject(new Error('no port')));
    });
  });
}

async function waitForPort(port: number): Promise<void> {
  for (let attempt = 0; attempt < 100; attempt++) {
    const open = await new Promise<boolean>(resolve => {
      const socket = net.connect({ host: '127.0.0.1', port });
      socket.once('connect', () => { socket.destroy(); resolve(true); });
      socket.once('error', () => resolve(false));
    });
    if (open) return;
    await new Promise(resolve => setTimeout(resolve, 10));
  }
  throw new Error('Timed out waiting for Redis integration server');
}

async function waitForOutput(child: ChildProcess, pattern: RegExp): Promise<void> {
  return new Promise((resolve, reject) => {
    let seen = '';
    const timer = setTimeout(() => reject(new Error(`Timed out waiting for ${pattern}; output: ${seen}`)), 10_000);
    const onData = (chunk: Buffer) => {
      seen += chunk.toString();
      if (!pattern.test(seen)) return;
      clearTimeout(timer);
      child.stdout?.off('data', onData);
      child.stderr?.off('data', onData);
      resolve();
    };
    child.stdout?.on('data', onData);
    child.stderr?.on('data', onData);
    child.once('exit', code => {
      clearTimeout(timer);
      reject(new Error(`Entry process exited before readiness (${code}); output: ${seen}`));
    });
  });
}

async function stopChild(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  await new Promise<void>(resolve => {
    const timer = setTimeout(() => { if (child.exitCode === null) child.kill('SIGKILL'); }, 2_000);
    child.once('exit', () => { clearTimeout(timer); resolve(); });
    child.kill('SIGTERM');
  });
}

async function signedGet(port: number, headers: Record<string, string>): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method: 'GET', path: '/ping', headers }, response => {
      response.resume();
      response.once('end', () => resolve(response.statusCode ?? 0));
    });
    req.once('error', reject);
    req.end();
  });
}

async function wsRequest(url: string, message: OverlayMessage): Promise<OverlayMessage> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    const timer = setTimeout(() => { ws.close(); reject(new Error('websocket request timed out')); }, 5_000);
    ws.once('open', () => ws.send(JSON.stringify(message)));
    ws.once('message', raw => {
      clearTimeout(timer);
      ws.close();
      resolve(JSON.parse(raw.toString()) as OverlayMessage);
    });
    ws.once('error', error => { clearTimeout(timer); reject(error); });
  });
}

describe.skipIf(!enabled)('RedisReplayStore integration', () => {
  it('atomically rejects a duplicate from separate pooled clients against real Redis', async () => {
    const port = await freePort();
    const password = 'lattice-integration-secret';
    server = spawn(process.env.LATTICE_REDIS_SERVER_BIN || 'redis-server', [
      '--port', String(port), '--bind', '127.0.0.1', '--save', '', '--appendonly', 'no', '--requirepass', password,
    ], { stdio: 'ignore' });
    await waitForPort(port);
    const url = `redis://:${password}@127.0.0.1:${port}/0`;
    const first = new RedisReplayStore(url, { poolSize: 2 });
    const second = new RedisReplayStore(url, { poolSize: 2 });
    try {
      const results = await Promise.all([
        first.claim('agent:2026-08-24:nonce', 30_000),
        second.claim('agent:2026-08-24:nonce', 30_000),
      ]);
      expect(results.filter(Boolean)).toHaveLength(1);
    } finally {
      first.close();
      second.close();
    }
  });

  it('rejects a replay across two separate Entry processes backed by real Redis', async () => {
    const redisPort = await freePort();
    const password = 'lattice-multiprocess-secret';
    server = spawn(process.env.LATTICE_REDIS_SERVER_BIN || 'redis-server', [
      '--port', String(redisPort), '--bind', '127.0.0.1', '--save', '', '--appendonly', 'no', '--requirepass', password,
    ], { stdio: 'ignore' });
    await waitForPort(redisPort);
    const redisUrl = `redis://:${password}@127.0.0.1:${redisPort}/0`;

    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lat-entry-replicas-'));
    homes.push(home);
    process.env.LATTICE_HOME = home;
    vi.resetModules();
    const state = await import('../node/state');
    state.initDirs();
    const ca = generateKeyPair();
    const overlaySecret = crypto.randomBytes(32).toString('base64');
    state.saveCA({
      caId: 'ca.integration', publicKey: ca.publicKey, privateKey: ca.privateKey,
      overlaySecret, createdAt: new Date().toISOString(),
    });
    const agent = generateKeyPair();
    state.saveAgent('bot1', { cert: {}, publicKey: agent.publicKey, privateKey: agent.privateKey, createdAt: new Date().toISOString() });
    const relayPort = await freePort();
    const [firstPort, secondPort] = await Promise.all([freePort(), freePort()]);
    const relay = new WebSocketServer({ port: relayPort, host: '127.0.0.1' });
    relay.on('connection', ws => ws.on('message', raw => {
      const request = JSON.parse(raw.toString()) as OverlayMessage;
      ws.send(JSON.stringify(signOverlayMessage({
        id: request.id, type: 'response', source: 'relay', destination: request.source,
        payload: { status: 200, headers: { 'content-type': 'text/plain' }, body: Buffer.from('ok').toString('base64') },
        trace: request.trace,
      }, overlaySecret)));
    }));
    await new Promise<void>((resolve, reject) => {
      relay.once('listening', resolve);
      relay.once('error', reject);
    });
    const tsNode = path.join(process.cwd(), 'node_modules/.bin/ts-node');
    const startEntry = (port: number) => spawn(tsNode, [
      '-e',
      `const { EntryNode } = require('./node/entry'); new EntryNode({ port: ${port}, relayUrls: ['ws://127.0.0.1:${relayPort}'], nodeConfig: null });`,
    ], {
      cwd: process.cwd(),
      env: { ...process.env, LATTICE_HOME: home, LATTICE_REPLAY_REDIS_URL: redisUrl },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const first = startEntry(firstPort);
    const second = startEntry(secondPort);
    try {
      await Promise.all([waitForOutput(first, /Listening for agents/), waitForOutput(second, /Listening for agents/)]);
      const timestamp = new Date().toISOString();
      const body = Buffer.alloc(0);
      const headers = {
        host: 'echo.lattice',
        'x-lattice-agent': 'bot1',
        'x-lattice-timestamp': timestamp,
        'x-lattice-nonce': 'multiprocess-replay-0001',
        'x-lattice-signature': signData(requestSignaturePayload({
          agent: 'bot1', method: 'GET', host: 'echo.lattice', url: '/ping', timestamp, bodyHash: hashRequestBody(body),
        }), agent.privateKey),
      };
      const outcomes = await Promise.all([signedGet(firstPort, headers), signedGet(secondPort, headers)]);
      expect(outcomes.sort()).toEqual([200, 401]);
    } finally {
      await Promise.all([stopChild(first), stopChild(second)]);
      await new Promise<void>(resolve => relay.close(() => resolve()));
    }
  });

  it('rejects a replay across independent Entry state directories using a portable issuer certificate', async () => {
    const redisPort = await freePort();
    const password = 'lattice-portable-entry-replicas-secret';
    server = spawn(process.env.LATTICE_REDIS_SERVER_BIN || 'redis-server', [
      '--port', String(redisPort), '--bind', '127.0.0.1', '--save', '', '--appendonly', 'no', '--requirepass', password,
    ], { stdio: 'ignore' });
    await waitForPort(redisPort);
    const redisUrl = `redis://:${password}@127.0.0.1:${redisPort}/0`;

    const [firstHome, secondHome] = [
      fs.mkdtempSync(path.join(os.tmpdir(), 'lat-entry-cell-a-')),
      fs.mkdtempSync(path.join(os.tmpdir(), 'lat-entry-cell-b-')),
    ];
    homes.push(firstHome, secondHome);
    const cellCa = generateKeyPair();
    const overlaySecret = crypto.randomBytes(32).toString('base64');
    for (const home of [firstHome, secondHome]) {
      process.env.LATTICE_HOME = home;
      vi.resetModules();
      const state = await import('../node/state');
      state.initDirs();
      // Same local-mode overlay trust, but no shared agent files, policy files,
      // node keys, or cache paths between Entry replicas.
      state.saveCA({
        caId: 'cell-local-ca', publicKey: cellCa.publicKey, privateKey: cellCa.privateKey,
        overlaySecret, createdAt: new Date().toISOString(),
      });
    }

    const issuer = new LatticeCA('agents.example');
    const agent = generateKeyPair();
    const signedAgent = issuer.issueAgentCert({
      agent_id: 'bot1', owner_org: 'example', agent_type: 'worker', version: '1',
      public_key: agent.publicKey, allowed_capability_classes: ['lp://echo.lattice:ping'],
      forbidden_capability_classes: [], expires_in_days: 1,
    });
    const relayPort = await freePort();
    const [firstPort, secondPort] = await Promise.all([freePort(), freePort()]);
    const relay = new WebSocketServer({ port: relayPort, host: '127.0.0.1' });
    relay.on('connection', ws => ws.on('message', raw => {
      const request = JSON.parse(raw.toString()) as OverlayMessage;
      ws.send(JSON.stringify(signOverlayMessage({
        id: request.id, type: 'response', source: 'relay', destination: request.source,
        payload: { status: 200, headers: { 'content-type': 'text/plain' }, body: Buffer.from('ok').toString('base64') },
        trace: request.trace,
      }, overlaySecret)));
    }));
    await new Promise<void>((resolve, reject) => {
      relay.once('listening', resolve);
      relay.once('error', reject);
    });
    const tsNode = path.join(process.cwd(), 'node_modules/.bin/ts-node');
    const config = JSON.stringify({ agentTrust: { issuers: [{ issuer_id: issuer.id, public_key: issuer.publicKey }] } });
    const startEntry = (home: string, port: number) => spawn(tsNode, [
      '-e',
      `const { EntryNode } = require('./node/entry'); new EntryNode({ port: ${port}, relayUrls: ['ws://127.0.0.1:${relayPort}'], nodeConfig: ${config} });`,
    ], {
      cwd: process.cwd(),
      env: { ...process.env, LATTICE_HOME: home, LATTICE_REPLAY_REDIS_URL: redisUrl },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const first = startEntry(firstHome, firstPort);
    const second = startEntry(secondHome, secondPort);
    try {
      await Promise.all([waitForOutput(first, /Listening for agents/), waitForOutput(second, /Listening for agents/)]);
      const timestamp = new Date().toISOString();
      const body = Buffer.alloc(0);
      const headers = {
        host: 'echo.lattice',
        'x-lattice-agent': 'bot1',
        'x-lattice-timestamp': timestamp,
        'x-lattice-nonce': 'portable-multiprocess-replay-0001',
        'x-lattice-signature': signData(requestSignaturePayload({
          agent: 'bot1', method: 'GET', host: 'echo.lattice', url: '/ping', timestamp, bodyHash: hashRequestBody(body),
        }), agent.privateKey),
        'x-lattice-agent-certificate': Buffer.from(JSON.stringify(signedAgent), 'utf8').toString('base64url'),
      };
      const outcomes = await Promise.all([signedGet(firstPort, headers), signedGet(secondPort, headers)]);
      expect(outcomes.sort()).toEqual([200, 401]);
    } finally {
      await Promise.all([stopChild(first), stopChild(second)]);
      await new Promise<void>(resolve => relay.close(() => resolve()));
    }
  });

  it('deduplicates an action across two separate Gateway processes backed by real Redis', async () => {
    const redisPort = await freePort();
    const password = 'lattice-gateway-replicas-secret';
    server = spawn(process.env.LATTICE_REDIS_SERVER_BIN || 'redis-server', [
      '--port', String(redisPort), '--bind', '127.0.0.1', '--save', '', '--appendonly', 'no', '--requirepass', password,
    ], { stdio: 'ignore' });
    await waitForPort(redisPort);
    const redisUrl = `redis://:${password}@127.0.0.1:${redisPort}/0`;

    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lat-gateway-replicas-'));
    homes.push(home);
    process.env.LATTICE_HOME = home;
    vi.resetModules();
    const state = await import('../node/state');
    state.initDirs();
    const ca = generateKeyPair();
    const overlaySecret = crypto.randomBytes(32).toString('base64');
    state.saveCA({
      caId: 'ca.integration', publicKey: ca.publicKey, privateKey: ca.privateKey,
      overlaySecret, createdAt: new Date().toISOString(),
    });
    const relayPubkey = state.getOrCreateOverlayKeyPair().publicKey;
    const agent = generateKeyPair();
    const { PolicyLoader } = await import('../node/policy-loader');
    const policy = new PolicyLoader();
    policy.grant('bot1', 'lp://echo.lattice', ['ping']);
    policy.pinAgentPublicKey('bot1', agent.publicKey);

    const [backendPort, firstPort, secondPort] = await Promise.all([freePort(), freePort(), freePort()]);
    let backendCalls = 0;
    const backend = http.createServer((_request, response) => {
      backendCalls++;
      response.writeHead(200, { 'content-type': 'text/plain' });
      response.end('ok');
    });
    await new Promise<void>((resolve, reject) => backend.listen(backendPort, '127.0.0.1', resolve).once('error', reject));
    const tsNode = path.join(process.cwd(), 'node_modules/.bin/ts-node');
    const startGateway = (port: number) => spawn(tsNode, [
      '-e',
      `const { ServiceGateway } = require('./node/gateway'); new ServiceGateway('lp://echo.lattice', 'http://127.0.0.1:${backendPort}', { port: ${port}, nodeConfig: null });`,
    ], {
      cwd: process.cwd(),
      env: { ...process.env, LATTICE_HOME: home, LATTICE_REPLAY_REDIS_URL: redisUrl },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const first = startGateway(firstPort);
    const second = startGateway(secondPort);
    try {
      await Promise.all([waitForOutput(first, /Gateway.*listening/), waitForOutput(second, /Gateway.*listening/)]);
      const timestamp = new Date().toISOString();
      const body = Buffer.alloc(0);
      const signature = signData(requestSignaturePayload({
        agent: 'bot1', method: 'GET', host: 'echo.lattice', url: '/ping', timestamp, bodyHash: hashRequestBody(body),
      }), agent.privateKey);
      const request = signOverlayMessage({
        id: 'multiprocess-gateway-replay', type: 'request', source: 'bot1', destination: 'lp://echo.lattice',
        payload: {
          method: 'GET', url: '/ping', headers: { host: 'echo.lattice' }, body: '',
          agent_proof: {
            agent: 'bot1', public_key: agent.publicKey, signature, timestamp,
            nonce: 'multiprocess-gateway-replay-0001', body_hash: hashRequestBody(body), host: 'echo.lattice',
          },
        },
        trace: ['entry', 'relay'], source_pubkey: relayPubkey, source_node_role: 'relay',
      }, overlaySecret);
      const outcomes = await Promise.all([
        wsRequest(`ws://127.0.0.1:${firstPort}`, request),
        wsRequest(`ws://127.0.0.1:${secondPort}`, request),
      ]);
      expect(outcomes.map(result => result.payload.status).sort()).toEqual([200, 401]);
      expect(backendCalls).toBe(1);
    } finally {
      await Promise.all([stopChild(first), stopChild(second)]);
      await new Promise<void>(resolve => backend.close(() => resolve()));
    }
  });

  it('deduplicates a portable-issuer action across Gateway state directories with separate journals', async () => {
    const redisPort = await freePort();
    const password = 'lattice-portable-gateway-replicas-secret';
    server = spawn(process.env.LATTICE_REDIS_SERVER_BIN || 'redis-server', [
      '--port', String(redisPort), '--bind', '127.0.0.1', '--save', '', '--appendonly', 'no', '--requirepass', password,
    ], { stdio: 'ignore' });
    await waitForPort(redisPort);
    const redisUrl = `redis://:${password}@127.0.0.1:${redisPort}/0`;

    const [firstHome, secondHome] = [
      fs.mkdtempSync(path.join(os.tmpdir(), 'lat-gateway-cell-a-')),
      fs.mkdtempSync(path.join(os.tmpdir(), 'lat-gateway-cell-b-')),
    ];
    homes.push(firstHome, secondHome);
    const cellCa = generateKeyPair();
    const overlaySecret = crypto.randomBytes(32).toString('base64');
    for (const home of [firstHome, secondHome]) {
      process.env.LATTICE_HOME = home;
      vi.resetModules();
      const state = await import('../node/state');
      state.initDirs();
      state.saveCA({
        caId: 'cell-local-ca', publicKey: cellCa.publicKey, privateKey: cellCa.privateKey,
        overlaySecret, createdAt: new Date().toISOString(),
      });
    }

    const issuer = new LatticeCA('agents.example');
    const agent = generateKeyPair();
    const signedAgent = issuer.issueAgentCert({
      agent_id: 'bot1', owner_org: 'example', agent_type: 'worker', version: '1',
      public_key: agent.publicKey, allowed_capability_classes: ['lp://echo.lattice:ping'],
      forbidden_capability_classes: [], expires_in_days: 1,
    });
    const [backendPort, firstPort, secondPort] = await Promise.all([freePort(), freePort(), freePort()]);
    let backendCalls = 0;
    const backend = http.createServer((_request, response) => {
      backendCalls++;
      response.writeHead(200, { 'content-type': 'text/plain' });
      response.end('ok');
    });
    await new Promise<void>((resolve, reject) => backend.listen(backendPort, '127.0.0.1', resolve).once('error', reject));
    const tsNode = path.join(process.cwd(), 'node_modules/.bin/ts-node');
    const config = JSON.stringify({ gateway: { issuerGrants: [{
      issuer_id: issuer.id,
      public_key: issuer.publicKey,
      services: [{ address: 'lp://echo.lattice', actions: ['ping'] }],
    }] } });
    const startGateway = (home: string, port: number) => spawn(tsNode, [
      '-e',
      `const { ServiceGateway } = require('./node/gateway'); new ServiceGateway('lp://echo.lattice', 'http://127.0.0.1:${backendPort}', { port: ${port}, nodeConfig: ${config} });`,
    ], {
      cwd: process.cwd(),
      env: { ...process.env, LATTICE_HOME: home, LATTICE_REPLAY_REDIS_URL: redisUrl },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    const first = startGateway(firstHome, firstPort);
    const second = startGateway(secondHome, secondPort);
    try {
      await Promise.all([waitForOutput(first, /Gateway.*listening/), waitForOutput(second, /Gateway.*listening/)]);
      const timestamp = new Date().toISOString();
      const body = Buffer.alloc(0);
      const signature = signData(requestSignaturePayload({
        agent: 'bot1', method: 'GET', host: 'echo.lattice', url: '/ping', timestamp, bodyHash: hashRequestBody(body),
      }), agent.privateKey);
      const relayKey = generateNodeKeyPair().publicKey;
      const request = signOverlayMessage({
        id: 'portable-multiprocess-gateway-replay', type: 'request', source: 'bot1', destination: 'lp://echo.lattice',
        payload: {
          method: 'GET', url: '/ping', headers: { host: 'echo.lattice' }, body: '',
          agent_proof: {
            agent: 'bot1', public_key: agent.publicKey, signature, timestamp,
            nonce: 'portable-multiprocess-gateway-replay-0001', body_hash: hashRequestBody(body), host: 'echo.lattice',
            certificate: signedAgent,
          },
        },
        trace: ['entry', 'relay'], source_pubkey: relayKey, source_node_role: 'relay',
      }, overlaySecret);
      const outcomes = await Promise.all([
        wsRequest(`ws://127.0.0.1:${firstPort}`, request),
        wsRequest(`ws://127.0.0.1:${secondPort}`, request),
      ]);
      expect(outcomes.map(result => result.payload.status).sort()).toEqual([200, 401]);
      expect(backendCalls).toBe(1);
    } finally {
      await Promise.all([stopChild(first), stopChild(second)]);
      await new Promise<void>(resolve => backend.close(() => resolve()));
    }
  });
});
