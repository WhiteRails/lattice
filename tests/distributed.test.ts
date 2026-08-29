/**
 * Distributed overlay unit tests (isolate state via LATTICE_HOME + dynamic imports).
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import * as crypto from 'crypto';
import * as http from 'http';
import { spawn, type ChildProcessWithoutNullStreams } from 'child_process';

async function freshLatticeHome(): Promise<{ home: string }> {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lat-dist-'));
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
  return { home };
}

async function configureHome(home: string, fn: () => Promise<void>): Promise<void> {
  process.env.LATTICE_HOME = home;
  vi.resetModules();
  await fn();
}

async function overlayPubkey(home: string): Promise<string> {
  let pk = '';
  await configureHome(home, async () => {
    const { getOrCreateOverlayKeyPair } = await import('../node/state');
    pk = getOrCreateOverlayKeyPair().publicKey;
  });
  return pk;
}

async function onionNodeKeys(home: string) {
  let keys: Awaited<ReturnType<import('../node/node-crypto').NodeCryptoBackend['ensureKeys']>> = [];
  await configureHome(home, async () => {
    const { createNodeCryptoBackend } = await import('../node/node-crypto');
    keys = await createNodeCryptoBackend().ensureKeys(['identity', 'onion', 'gateway-encryption']);
  });
  return {
    identity: keys.find(key => key.purpose === 'identity')!,
    onion: keys.find(key => key.purpose === 'onion')!,
    gatewayEncryption: keys.find(key => key.purpose === 'gateway-encryption')!,
  };
}

function spawnCli(home: string, args: string[]): ChildProcessWithoutNullStreams {
  const tsNode = path.join(process.cwd(), 'node_modules/.bin/ts-node');
  return spawn(tsNode, ['cli/lattice.ts', ...args], {
    cwd: process.cwd(),
    env: { ...process.env, LATTICE_HOME: home },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

function waitForOutput(child: ChildProcessWithoutNullStreams, pattern: RegExp): Promise<void> {
  return new Promise((resolve, reject) => {
    let seen = '';
    const timer = setTimeout(() => reject(new Error(`Timed out waiting for ${pattern}. Seen: ${seen}`)), 10_000);
    const onData = (d: Buffer) => {
      seen += d.toString();
      if (pattern.test(seen)) {
        clearTimeout(timer);
        child.stdout.off('data', onData);
        child.stderr.off('data', onData);
        resolve();
      }
    };
    child.stdout.on('data', onData);
    child.stderr.on('data', onData);
    child.on('exit', code => {
      clearTimeout(timer);
      reject(new Error(`Process exited before ${pattern}: ${code}. Seen: ${seen}`));
    });
  });
}

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const srv = http.createServer();
    srv.once('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      srv.close(() => typeof addr === 'object' && addr ? resolve(addr.port) : reject(new Error('no port')));
    });
  });
}

describe('LpGatewayResolver + routing-cache (hybrid)', () => {
  let home: string;
  let homes: string[] = [];

  beforeEach(() => {
    vi.clearAllMocks();
    homes = [];
  });

  afterEach(() => {
    for (const h of homes) {
      if (h && fs.existsSync(h)) fs.rmSync(h, { recursive: true, force: true });
    }
    if (home && fs.existsSync(home)) fs.rmSync(home, { recursive: true, force: true });
    delete process.env.LATTICE_HOME;
    vi.resetModules();
  });

  it('local fallback registry when no chain + distributedMesh off', async () => {
    ({ home } = await freshLatticeHome());
    homes.push(home);
    const { LpGatewayResolver } = await import('../node/lp-resolver');
    const { getOrCreateOverlayKeyPair } = await import('../node/state');
    const resolver = new LpGatewayResolver(null, null);
    const r = await resolver.resolveDestination('lp://echo.lattice');
    expect(r.gatewayEndpoints[0]).toBe('ws://127.0.0.1:8889');
    expect(r.gatewayPubKeyB64).toBe(getOrCreateOverlayKeyPair().publicKey);
  });

  it('routing-cache HMAC round-trip', async () => {
    ({ home } = await freshLatticeHome());
    homes.push(home);
    const { upsertRoutingPayload, readRoutingCacheFile, ROUTING_PAYLOAD_VERSION } = await import('../node/routing-cache');
    upsertRoutingPayload(null, {
      version: ROUTING_PAYLOAD_VERSION,
      fqdn: 'echo.lattice',
      gatewayNodeLabel: 'gateway-a',
      gatewayPubKeyB64: 'Zm9v',
      gatewayEndpoints: ['ws://127.0.0.1:9999'],
    });
    const disk = readRoutingCacheFile(null);
    expect(disk?.routes['echo.lattice']?.payload.gatewayEndpoints[0]).toBe('ws://127.0.0.1:9999');
  });

  it('bounds local route-cache cardinality while allowing route renewal', async () => {
    ({ home } = await freshLatticeHome());
    homes.push(home);
    const {
      upsertRoutingPayload,
      ROUTING_PAYLOAD_VERSION,
      routingCacheMaxRoutesFromEnv,
      routingCacheMaxFileBytesFromEnv,
    } = await import('../node/routing-cache');
    const first = {
      version: ROUTING_PAYLOAD_VERSION,
      fqdn: 'one.lattice',
      gatewayPubKeyB64: 'Zm9v',
      gatewayEndpoints: ['ws://127.0.0.1:9999'],
    };
    upsertRoutingPayload(null, first, { maxRoutes: 1 });
    upsertRoutingPayload(null, { ...first, gatewayEndpoints: ['ws://127.0.0.1:9998'] }, { maxRoutes: 1 });
    expect(() => upsertRoutingPayload(null, {
      ...first,
      fqdn: 'two.lattice',
    }, { maxRoutes: 1 })).toThrow(/capacity/i);
    expect(routingCacheMaxRoutesFromEnv({ LATTICE_ROUTING_CACHE_MAX_ROUTES: '1000' })).toBe(1000);
    expect(() => routingCacheMaxRoutesFromEnv({ LATTICE_ROUTING_CACHE_MAX_ROUTES: 'invalid' })).toThrow(/integer/i);
    expect(routingCacheMaxFileBytesFromEnv({ LATTICE_ROUTING_CACHE_MAX_FILE_BYTES: '1048576' })).toBe(1048576);
    expect(() => routingCacheMaxFileBytesFromEnv({ LATTICE_ROUTING_CACHE_MAX_FILE_BYTES: 'invalid' })).toThrow(/integer/i);
  });

  it('bounds local lattice-node bootstrap records while allowing renewal', async () => {
    ({ home } = await freshLatticeHome());
    homes.push(home);
    const { upsertLatticeNodeLocalRecord } = await import('../node/routing-cache');
    const { generateNodeKeyPair } = await import('../node/session');
    const first = generateNodeKeyPair().publicKey;
    upsertLatticeNodeLocalRecord(null, 'entry-a', { overlayPubKeyB64: first }, { maxLatticeNodes: 1 });
    upsertLatticeNodeLocalRecord(null, 'entry-a', { overlayPubKeyB64: generateNodeKeyPair().publicKey }, { maxLatticeNodes: 1 });
    expect(() => upsertLatticeNodeLocalRecord(null, 'entry-b', {
      overlayPubKeyB64: generateNodeKeyPair().publicKey,
    }, { maxLatticeNodes: 1 })).toThrow(/lattice-node capacity/i);
  });

  it('bounds parsed routing files retained by one process', async () => {
    ({ home } = await freshLatticeHome());
    homes.push(home);
    const { upsertRoutingPayload, routingFileCacheSnapshot, ROUTING_PAYLOAD_VERSION } = await import('../node/routing-cache');
    for (let index = 0; index < 5; index++) {
      upsertRoutingPayload({ registry: { cacheFile: path.join(home, `routing-${index}.json`) } } as any, {
        version: ROUTING_PAYLOAD_VERSION,
        fqdn: `echo-${index}.lattice`, gatewayPubKeyB64: 'Zm9v', gatewayEndpoints: ['ws://127.0.0.1:9999'],
      });
    }
    expect(routingFileCacheSnapshot()).toEqual({ entries: 4, maxEntries: 4 });
  });

  it('distributedMesh on + no chain + no cache → not found', async () => {
    ({ home } = await freshLatticeHome());
    homes.push(home);
    const { saveNodeConfig } = await import('../node/node-config');
    const { LpGatewayResolver, LpRoutingNotFoundError } = await import('../node/lp-resolver');
    saveNodeConfig({ nodeId: 'relay-a', roles: ['relay'], distributedMesh: true, overlayProtocol: 'onion-v1' });
    const yaml = (await import('../node/node-config')).loadNodeConfig();
    const resolver = new LpGatewayResolver(yaml, null);
    await expect(resolver.resolveDestination('lp://echo.lattice')).rejects.toThrow(LpRoutingNotFoundError);
  });

  it('imports chain-committed route bundles across different overlay secrets', async () => {
    ({ home } = await freshLatticeHome());
    homes.push(home);
    let routing = await import('../node/routing-cache');
    routing.upsertRoutingPayload(null, {
      version: routing.ROUTING_PAYLOAD_VERSION,
      fqdn: 'echo.lattice',
      gatewayNodeLabel: 'gateway-a',
      gatewayPubKeyB64: 'Zm9v',
      gatewayEndpoints: ['wss://gateway.example:8889'],
    });
    const bundle = routing.exportRoutingBundle(null, 'echo.lattice');

    ({ home } = await freshLatticeHome());
    homes.push(home);
    routing = await import('../node/routing-cache');
    routing.importRoutingBundle(null, bundle);
    const disk = routing.readRoutingCacheFile(null);
    expect(disk?.routes['echo.lattice']?.payload.gatewayNodeLabel).toBe('gateway-a');
    expect(disk?.routes['echo.lattice']?.payload.gatewayEndpoints[0]).toBe('wss://gateway.example:8889');
  });

  it('validates distributed peer labels, roles, registration, and pubkeys', async () => {
    ({ home } = await freshLatticeHome());
    homes.push(home);
    const { upsertLatticeNodeLocalRecord } = await import('../node/routing-cache');
    const { validateDistributedPeer } = await import('../node/peer-identity');
    const { generateNodeKeyPair } = await import('../node/session');
    const peerPub = generateNodeKeyPair().publicKey;

    upsertLatticeNodeLocalRecord(null, 'entry-a', {
      overlayPubKeyB64: peerPub,
      roleBitmask: 1,
    });

    const baseMsg: any = {
      id: 'm1',
      type: 'request',
      source: 'bot1',
      destination: 'lp://echo.lattice',
      payload: {},
      trace: [],
      source_pubkey: peerPub,
      source_node_label: 'entry-a',
      source_node_role: 'entry',
    };

    await expect(validateDistributedPeer({
      distributedMesh: true,
      cfg: null,
      chain: null,
      msg: baseMsg,
      expectedRole: 'entry',
    })).resolves.toMatchObject({ ok: true });

    await expect(validateDistributedPeer({
      distributedMesh: true,
      cfg: null,
      chain: null,
      msg: { ...baseMsg, source_node_label: undefined },
      expectedRole: 'entry',
    })).resolves.toMatchObject({ ok: false });

    await expect(validateDistributedPeer({
      distributedMesh: true,
      cfg: null,
      chain: null,
      msg: { ...baseMsg, source_node_role: 'gateway' },
      expectedRole: 'entry',
    })).resolves.toMatchObject({ ok: false });

    await expect(validateDistributedPeer({
      distributedMesh: true,
      cfg: null,
      chain: null,
      msg: { ...baseMsg, source_pubkey: generateNodeKeyPair().publicKey },
      expectedRole: 'entry',
    })).resolves.toMatchObject({ ok: false });
  });

  it('round-trips Entry → Relay → Gateway across isolated homes without shared overlaySecret', async () => {
    let relayPorts: number[];
    let gatewayPort: number;
    let entryPort: number;
    let backendPort: number;
    try {
      relayPorts = await Promise.all([freePort(), freePort(), freePort()]);
      gatewayPort = await freePort();
      entryPort = await freePort();
      backendPort = await freePort();
    } catch (e: any) {
      console.warn(`Skipping socket E2E: cannot bind localhost in this environment (${e?.message ?? e})`);
      return;
    }

    const entryHome = (await freshLatticeHome()).home;
    const relayHomes = [await freshLatticeHome(), await freshLatticeHome(), await freshLatticeHome()];
    const gatewayHome = (await freshLatticeHome()).home;
    const hiddenGatewayHome = (await freshLatticeHome()).home;
    homes.push(entryHome, ...relayHomes.map(value => value.home), gatewayHome, hiddenGatewayHome);

    const entryPk = await overlayPubkey(entryHome);
    const relayPks: string[] = [];
    for (const value of relayHomes) relayPks.push(await overlayPubkey(value.home));
    const gatewayPk = await overlayPubkey(gatewayHome);
    const hiddenGatewayPk = await overlayPubkey(hiddenGatewayHome);
    const entryNodeKeys = await onionNodeKeys(entryHome);
    const relayNodeKeys: Awaited<ReturnType<typeof onionNodeKeys>>[] = [];
    for (const value of relayHomes) relayNodeKeys.push(await onionNodeKeys(value.home));
    const gatewayNodeKeys = await onionNodeKeys(gatewayHome);
    const hiddenGatewayNodeKeys = await onionNodeKeys(hiddenGatewayHome);
    const entryOperator = '11'.repeat(32);
    const relayOperators = ['22'.repeat(32), '44'.repeat(32), '55'.repeat(32)];
    const relayLabels = ['relay-a', 'relay-b', 'relay-c'];
    const gatewayOperator = '33'.repeat(32);
    const hiddenGatewayOperator = '66'.repeat(32);
    let agentPublicKey = '';

    await configureHome(entryHome, async () => {
      const { saveNodeConfig } = await import('../node/node-config');
      const { upsertLatticeNodeLocalRecord, upsertRoutingPayload, ROUTING_PAYLOAD_VERSION } = await import('../node/routing-cache');
      const { saveAgent, loadCA } = await import('../node/state');
      const { LatticeCA } = await import('../core/ca');
      const { generateKeyPair } = await import('../core/identity');
      saveNodeConfig({
        nodeId: 'entry-a',
        roles: ['entry'],
        distributedMesh: true,
        overlayProtocol: 'onion-v1',
        circuit: { allowInsecureLoopbackTests: true },
        bind: { entry: `127.0.0.1:${entryPort}` },
        upstreamRelays: [{ label: 'relay-a', url: `ws://127.0.0.1:${relayPorts[0]}` }],
      });
      for (let index = 0; index < 3; index++) {
        upsertLatticeNodeLocalRecord(null, relayLabels[index]!, {
          overlayPubKeyB64: relayPks[index]!, identityPubKeyB64: relayNodeKeys[index]!.identity.publicKey,
          onionPubKeyB64Url: relayNodeKeys[index]!.onion.publicKey, operatorId: relayOperators[index]!,
          endpoint: `ws://127.0.0.1:${relayPorts[index]}`, roleBitmask: 2,
        });
      }
      upsertLatticeNodeLocalRecord(null, 'gateway-a', {
        overlayPubKeyB64: gatewayPk, identityPubKeyB64: gatewayNodeKeys.identity.publicKey,
        onionPubKeyB64Url: gatewayNodeKeys.onion.publicKey, operatorId: gatewayOperator, roleBitmask: 4,
      });
      upsertLatticeNodeLocalRecord(null, 'gateway-hidden', {
        overlayPubKeyB64: hiddenGatewayPk,
        identityPubKeyB64: hiddenGatewayNodeKeys.identity.publicKey,
        onionPubKeyB64Url: hiddenGatewayNodeKeys.onion.publicKey,
        operatorId: hiddenGatewayOperator,
        roleBitmask: 4,
      });
      upsertRoutingPayload(null, {
        version: ROUTING_PAYLOAD_VERSION,
        fqdn: 'echo.lattice',
        gatewayNodeLabel: 'gateway-a',
        gatewayPubKeyB64: gatewayPk,
        gatewayEndpoints: [`ws://127.0.0.1:${gatewayPort}`],
        gatewayEncryptionKeyId: gatewayNodeKeys.gatewayEncryption.keyId,
        gatewayEncryptionPubKeyB64Url: gatewayNodeKeys.gatewayEncryption.publicKey,
        hpkeSuite: 'DHKEM-X25519-HKDF-SHA256/HKDF-SHA256/AES-256-GCM',
        delivery: { mode: 'public' },
      });
      const hiddenToken = crypto.createHmac('sha256', hiddenGatewayNodeKeys.gatewayEncryption.keyId)
        .update('relay-a\0echo-hidden.lattice', 'utf8').digest('base64url');
      upsertRoutingPayload(null, {
        version: ROUTING_PAYLOAD_VERSION,
        fqdn: 'echo-hidden.lattice',
        gatewayNodeLabel: 'gateway-hidden',
        gatewayPubKeyB64: hiddenGatewayPk,
        gatewayEndpoints: [],
        gatewayEncryptionKeyId: hiddenGatewayNodeKeys.gatewayEncryption.keyId,
        gatewayEncryptionPubKeyB64Url: hiddenGatewayNodeKeys.gatewayEncryption.publicKey,
        hpkeSuite: 'DHKEM-X25519-HKDF-SHA256/HKDF-SHA256/AES-256-GCM',
        delivery: {
          mode: 'hidden',
          rendezvous: [{
            nodeLabel: 'relay-a', endpoint: `ws://127.0.0.1:${relayPorts[0]}`,
            token: hiddenToken, expiresAt: new Date(Date.now() + 5 * 60_000).toISOString(),
          }],
        },
      });
      const caState = loadCA();
      const ca = LatticeCA.fromKeyPair(caState.caId, { publicKey: caState.publicKey, privateKey: caState.privateKey });
      const keys = generateKeyPair();
      agentPublicKey = keys.publicKey;
      const signed = ca.issueAgentCert({
        agent_id: 'agent:local:bot1',
        owner_org: 'local',
        agent_type: 'autonomous',
        version: '1.0',
        public_key: keys.publicKey,
        allowed_capability_classes: [],
        forbidden_capability_classes: [],
        expires_in_days: 365,
      });
      saveAgent('bot1', {
        cert: signed.cert,
        signedCert: signed,
        publicKey: keys.publicKey,
        privateKey: keys.privateKey,
        createdAt: new Date().toISOString(),
      });
    });

    for (let index = 0; index < 3; index++) {
      await configureHome(relayHomes[index]!.home, async () => {
        const { saveNodeConfig } = await import('../node/node-config');
        const { upsertLatticeNodeLocalRecord } = await import('../node/routing-cache');
        saveNodeConfig({
          nodeId: relayLabels[index]!,
          roles: ['relay'],
          distributedMesh: true,
          overlayProtocol: 'onion-v1',
          circuit: { allowInsecureLoopbackTests: true },
          bind: { relay: `127.0.0.1:${relayPorts[index]}` },
        });
        upsertLatticeNodeLocalRecord(null, 'entry-a', {
          overlayPubKeyB64: entryPk, identityPubKeyB64: entryNodeKeys.identity.publicKey,
          onionPubKeyB64Url: entryNodeKeys.onion.publicKey, operatorId: entryOperator, roleBitmask: 1,
        });
        upsertLatticeNodeLocalRecord(null, 'gateway-a', {
          overlayPubKeyB64: gatewayPk, identityPubKeyB64: gatewayNodeKeys.identity.publicKey,
          onionPubKeyB64Url: gatewayNodeKeys.onion.publicKey, operatorId: gatewayOperator, roleBitmask: 4,
        });
        upsertLatticeNodeLocalRecord(null, 'gateway-hidden', {
          overlayPubKeyB64: hiddenGatewayPk,
          identityPubKeyB64: hiddenGatewayNodeKeys.identity.publicKey,
          onionPubKeyB64Url: hiddenGatewayNodeKeys.onion.publicKey,
          operatorId: hiddenGatewayOperator,
          roleBitmask: 4,
        });
        for (let peerIndex = 0; peerIndex < 3; peerIndex++) {
          upsertLatticeNodeLocalRecord(null, relayLabels[peerIndex]!, {
            overlayPubKeyB64: relayPks[peerIndex]!,
            identityPubKeyB64: relayNodeKeys[peerIndex]!.identity.publicKey,
            onionPubKeyB64Url: relayNodeKeys[peerIndex]!.onion.publicKey,
            operatorId: relayOperators[peerIndex]!,
            endpoint: `ws://127.0.0.1:${relayPorts[peerIndex]}`,
            roleBitmask: 2,
          });
        }
      });
    }

    await configureHome(gatewayHome, async () => {
      const { saveNodeConfig } = await import('../node/node-config');
      const { upsertLatticeNodeLocalRecord } = await import('../node/routing-cache');
      const { PolicyLoader } = await import('../node/policy-loader');
      saveNodeConfig({
        nodeId: 'gateway-a',
        roles: ['gateway'],
        distributedMesh: true,
        overlayProtocol: 'onion-v1',
        circuit: { allowInsecureLoopbackTests: true },
        bind: { gateway: `127.0.0.1:${gatewayPort}` },
      });
      for (let index = 0; index < 3; index++) {
        upsertLatticeNodeLocalRecord(null, relayLabels[index]!, {
          overlayPubKeyB64: relayPks[index]!, identityPubKeyB64: relayNodeKeys[index]!.identity.publicKey,
          onionPubKeyB64Url: relayNodeKeys[index]!.onion.publicKey, operatorId: relayOperators[index]!,
          endpoint: `ws://127.0.0.1:${relayPorts[index]}`, roleBitmask: 2,
        });
      }
      const policy = new PolicyLoader();
      policy.grant('bot1', 'lp://echo.lattice', ['ping']);
      policy.pinAgentPublicKey('bot1', agentPublicKey);
    });

    await configureHome(hiddenGatewayHome, async () => {
      const { saveNodeConfig } = await import('../node/node-config');
      const { upsertLatticeNodeLocalRecord } = await import('../node/routing-cache');
      const { PolicyLoader } = await import('../node/policy-loader');
      saveNodeConfig({
        nodeId: 'gateway-hidden',
        roles: ['gateway'],
        distributedMesh: true,
        overlayProtocol: 'onion-v1',
        circuit: { allowInsecureLoopbackTests: true },
        gateway: {
          mode: 'hidden',
          hiddenServiceAddress: 'lp://echo-hidden.lattice',
          rendezvousRelays: [{ label: 'relay-a', url: `ws://127.0.0.1:${relayPorts[0]}` }],
        },
      });
      for (let index = 0; index < 3; index++) {
        upsertLatticeNodeLocalRecord(null, relayLabels[index]!, {
          overlayPubKeyB64: relayPks[index]!, identityPubKeyB64: relayNodeKeys[index]!.identity.publicKey,
          onionPubKeyB64Url: relayNodeKeys[index]!.onion.publicKey, operatorId: relayOperators[index]!,
          endpoint: `ws://127.0.0.1:${relayPorts[index]}`, roleBitmask: 2,
        });
      }
      const policy = new PolicyLoader();
      policy.grant('bot1', 'lp://echo-hidden.lattice', ['ping']);
      policy.pinAgentPublicKey('bot1', agentPublicKey);
    });

    const backend = http.createServer((_req, res) => {
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('pong');
    });
    await new Promise<void>((resolve, reject) => {
      backend.once('error', reject);
      backend.listen(backendPort, '127.0.0.1', () => resolve());
    });

    const children: ChildProcessWithoutNullStreams[] = [];
    let nodeOutput = '';
    try {
      const gw = spawnCli(gatewayHome, ['node', 'start', '--role', 'gateway', '--service', 'lp://echo.lattice', '--target', `http://127.0.0.1:${backendPort}`]);
      children.push(gw);
      gw.stdout.on('data', d => { nodeOutput += d.toString(); });
      gw.stderr.on('data', d => { nodeOutput += d.toString(); });
      await waitForOutput(gw, /Gateway.*listening/);

      for (const relayHome of relayHomes) {
        const relay = spawnCli(relayHome.home, ['node', 'start', '--role', 'relay']);
        children.push(relay);
        relay.stdout.on('data', d => { nodeOutput += d.toString(); });
        relay.stderr.on('data', d => { nodeOutput += d.toString(); });
        await waitForOutput(relay, /RelayNode.*Listening/);
      }

      const hiddenGateway = spawnCli(hiddenGatewayHome, [
        'node', 'start', '--role', 'gateway', '--service', 'lp://echo-hidden.lattice',
        '--target', `http://127.0.0.1:${backendPort}`,
      ]);
      children.push(hiddenGateway);
      hiddenGateway.stdout.on('data', d => { nodeOutput += d.toString(); });
      hiddenGateway.stderr.on('data', d => { nodeOutput += d.toString(); });
      await waitForOutput(hiddenGateway, /starting in HIDDEN mode/);

      const entry = spawnCli(entryHome, ['node', 'start', '--role', 'entry']);
      children.push(entry);
      entry.stdout.on('data', d => { nodeOutput += d.toString(); });
      entry.stderr.on('data', d => { nodeOutput += d.toString(); });
      await waitForOutput(entry, /EntryNode.*Listening/);

      const smoke = spawnCli(entryHome, [
        'mesh',
        'smoke',
        '--agent',
        'bot1',
        '--entry',
        `http://127.0.0.1:${entryPort}`,
        '--host',
        'echo.lattice',
        '--path',
        '/ping',
        '--expect-status',
        '200',
      ]);
      let out = '';
      smoke.stdout.on('data', d => { out += d.toString(); });
      smoke.stderr.on('data', d => { out += d.toString(); });
      const code = await new Promise<number | null>(resolve => smoke.on('exit', resolve));
      expect(code, `${out}\n${nodeOutput}`).toBe(0);
      expect(out).toContain('pong');

      const hiddenSmoke = spawnCli(entryHome, [
        'mesh', 'smoke', '--agent', 'bot1', '--entry', `http://127.0.0.1:${entryPort}`,
        '--host', 'echo-hidden.lattice', '--path', '/ping', '--expect-status', '200',
      ]);
      let hiddenOut = '';
      hiddenSmoke.stdout.on('data', d => { hiddenOut += d.toString(); });
      hiddenSmoke.stderr.on('data', d => { hiddenOut += d.toString(); });
      const hiddenCode = await new Promise<number | null>(resolve => hiddenSmoke.on('exit', resolve));
      expect(hiddenCode, `${hiddenOut}\n${nodeOutput}`).toBe(0);
      expect(hiddenOut).toContain('pong');
    } finally {
      children.forEach(child => child.kill());
      await new Promise<void>(resolve => backend.close(() => resolve()));
    }
  }, 30_000);
});
