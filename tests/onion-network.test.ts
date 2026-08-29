import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { WebSocketServer } from 'ws';
import { afterEach, describe, expect, it } from 'vitest';
import type { CircuitPath, CircuitRelayCandidate } from '../node/circuit-selector';
import { LocalNodeCryptoBackend } from '../node/node-crypto';
import { OnionCircuitClient, OnionRelayRuntime } from '../node/onion-network';
import type { OnionRegisteredPeer } from '../node/onion-network';

const dirs: string[] = [];
const servers: WebSocketServer[] = [];
const observedWireFrames: Buffer[] = [];

afterEach(async () => {
  observedWireFrames.length = 0;
  await Promise.all(servers.splice(0).map(server => new Promise<void>(resolve => server.close(() => resolve()))));
  for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

async function startRelay(
  label: string,
  operatorByte: string,
  exit: (payload: Buffer) => Promise<Buffer>,
  directory: Map<string, OnionRegisteredPeer>,
) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lattice-onion-net-'));
  dirs.push(dir);
  const backend = new LocalNodeCryptoBackend(path.join(dir, 'keys'));
  const [identity, onion] = await backend.ensureKeys(['identity', 'onion']);
  directory.set(label, { active: true, roleBitmask: 2, identityPubKeyB64: identity.publicKey });
  const cfg = {
    nodeId: label,
    roles: ['relay'] as const,
    distributedMesh: true,
    overlayProtocol: 'onion-v1' as const,
    circuit: { allowInsecureLoopbackTests: true },
  };
  const runtime = new OnionRelayRuntime(label, cfg, backend, exit, async peer => directory.get(peer) ?? null);
  const server = new WebSocketServer({ host: '127.0.0.1', port: 0, maxPayload: 16_384 });
  servers.push(server);
  server.on('connection', ws => ws.on('message', (raw, isBinary) => {
    if (isBinary && Buffer.isBuffer(raw)) observedWireFrames.push(Buffer.from(raw));
    runtime.handle(ws, raw, isBinary);
  }));
  await new Promise<void>((resolve, reject) => {
    server.once('listening', resolve);
    server.once('error', reject);
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('No relay address');
  const candidate: CircuitRelayCandidate = {
    label,
    endpoint: `ws://127.0.0.1:${address.port}`,
    operatorId: operatorByte.repeat(64),
    identityPubKeyB64: identity.publicKey,
    onionPubKeyB64Url: onion.publicKey,
  };
  return candidate;
}

describe('three-hop onion network', () => {
  it('builds CREATE2 -> EXTEND2 -> EXTEND2 and transports fragmented data through exact binary cells', async () => {
    const entryDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lattice-onion-entry-'));
    dirs.push(entryDir);
    const entryBackend = new LocalNodeCryptoBackend(path.join(entryDir, 'keys'));
    const entryIdentity = await entryBackend.currentKey('identity');
    const directory = new Map<string, OnionRegisteredPeer>([
      ['entry-a', { active: true, roleBitmask: 1, identityPubKeyB64: entryIdentity.publicKey }],
    ]);
    const observedAtExit: Buffer[] = [];
    const exitHandler = async (payload: Buffer) => {
      observedAtExit.push(Buffer.from(payload));
      return Buffer.concat([Buffer.from('response:'), payload]);
    };
    const guard = await startRelay('guard-a', '1', async () => { throw new Error('guard must not be exit'); }, directory);
    const middle = await startRelay('middle-b', '2', async () => { throw new Error('middle must not be exit'); }, directory);
    const terminal = await startRelay('exit-c', '3', exitHandler, directory);
    const circuitPath: CircuitPath = { guard, middle, terminal };
    const cfg = {
      nodeId: 'entry-a', roles: ['entry'] as const, distributedMesh: true,
      overlayProtocol: 'onion-v1' as const, circuit: { allowInsecureLoopbackTests: true },
    };
    const client = new OnionCircuitClient(circuitPath, 'entry-a', 'entry', cfg, entryBackend);
    await client.build();
    expect(client.state.snapshot().state).toBe('ready');
    expect(new Set(client.state.snapshot().linkCircuitIds).size).toBe(3);

    const request = Buffer.alloc(40_000);
    request.write('agent-secret-url-and-body', 0, 'utf8');
    const response = await client.request(request);
    expect(observedAtExit).toHaveLength(1);
    expect(observedAtExit[0]).toEqual(request);
    expect(response.subarray(0, 9).toString()).toBe('response:');
    expect(response.subarray(9)).toEqual(request);
    expect(observedWireFrames.length).toBeGreaterThan(6);
    expect(observedWireFrames.every(frame => frame.length === 16_384)).toBe(true);
    expect(Buffer.concat(observedWireFrames).includes(Buffer.from('agent-secret-url-and-body'))).toBe(false);
    client.destroy();
  }, 30_000);

  it('rejects plaintext WS unless the explicit loopback test exception is enabled', async () => {
    const directory = new Map<string, OnionRegisteredPeer>();
    const relay = await startRelay('guard-z', '4', async value => value, directory);
    const entryDir = fs.mkdtempSync(path.join(os.tmpdir(), 'lattice-onion-entry-'));
    dirs.push(entryDir);
    const entryBackend = new LocalNodeCryptoBackend(path.join(entryDir, 'keys'));
    const circuitPath: CircuitPath = { guard: relay, middle: relay, terminal: relay };
    expect(() => new OnionCircuitClient(circuitPath, 'entry-a', 'entry', {
      nodeId: 'entry-a', roles: ['entry'], distributedMesh: true, overlayProtocol: 'onion-v1',
    }, entryBackend)).toThrow(/WSS_REQUIRED/);
  });
});
