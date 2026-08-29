import { WebSocketServer, WebSocket } from 'ws';
import * as http from 'http';
import * as https from 'https';
import * as crypto from 'crypto';
import { OverlayMessage, parseOverlayMessage, signOverlayMessage, type AgentProof } from './message';
import { PolicyLoader } from './policy-loader';
import { isRevoked, loadCA, getOrCreateOverlayKeyPair, logPath, normalizeAgentName } from './state';
import { SessionManager, sessionMaxEntriesFromEnv } from './session';
import chalk from 'chalk';
import { controlBus } from './agent-control';
import { PowerAccumulationTracker } from '../core/pas';
import { verifyIncomingOverlayFromPeer, peerWireId } from './overlay-sign-key';
import type { LatticeNodeYaml, NodeChainConfig, UpstreamRelay } from './node-config';
import {
  distributedMeshEffective,
  loadNodeConfig,
  parseBindHostPort,
  requireDistributedNodeId,
  resolveNodeChainConfig,
  resolveGatewayMode,
  resolveGatewayIssuerGrants,
  resolveRendezvousRelays,
  resolveHiddenServiceAddress,
  resolveFederationUrls,
  assertOnionListenerTls,
  assertOnionWebSocketUrls,
  assertOnionOverlayRequired,
  onionOverlayEffective,
  resolveOnionCircuitConfig,
} from './node-config';
import { bindOverlayWebSocketServer, wsTlsClientOptions } from './ws-stack';
import { validateDistributedPeer } from './peer-identity';
import { postFederationAnnounce } from './federation-registry';
import { deriveSelfAuthAddress } from './self-auth';
import { ActionJournal, actionJournalOptionsFromEnv } from './action-journal';
import type { GatewayIssuerGrant } from './node-config';
import { IssuerCertificateCache } from './issuer-certificate-cache';
import { LpGatewayResolver } from './lp-resolver';
import { hashRequestBody, requestSignaturePayload, verifySignature } from '../core/identity';
import { getReplayWindowMs } from './nonce-store';
import { OverlayIngressLimiter, overlayIngressLimitsFromEnv } from './overlay-ingress';
import { replayStoreFromEnv, type ReplayStore } from './replay-store';
import { gatewayReplayKey } from './replay-keys';
import { federationReplicaUrls } from './rendezvous';
import { serveCellStatus } from './node-metrics';
import { createNodeCryptoBackend, type NodeCryptoBackend } from './node-crypto';
import { LATTICE_HPKE_SUITE, parseHpkeEnvelope, sealHpkeJson } from './hpke-envelope';
import { gatewayResponseSignaturePayload, parseE2eRequest, type E2eResponseUnsigned } from './e2e-message';
import { GuardSetStore, relayCandidatesFromRoutingCache, selectCircuitPath } from './circuit-selector';
import { readRoutingCacheFile } from './routing-cache';
import { OnionCircuitClient } from './onion-network';
import { createHiddenGatewayOperation } from './hidden-rendezvous';

const ALLOWED_BACKEND_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);
const HOP_BY_HOP_HEADERS = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade', 'host', 'content-length',
]);
// A response is re-encoded into the 1 MiB overlay frame. Keep enough room for
// base64 expansion, signed metadata and a bounded header set.
const MAX_BACKEND_RESPONSE_BYTES = 512 * 1024;
const MAX_BACKEND_RESPONSE_HEADER_BYTES = 32 * 1024;
const DEFAULT_BACKEND_RESPONSE_TIMEOUT_MS = 30_000;
const DEFAULT_BACKEND_MAX_SOCKETS = 4_096;

export interface ServiceGatewayOptions {
  port?: number;
  bindHostPort?: string;
  nodeConfig?: LatticeNodeYaml | null;
  replayStore?: ReplayStore;
}

interface GatewayE2eResponseContext {
  requestId: string;
  routeHash: string;
  responseKeyId: string;
  responsePublicKey: string;
  transportDestination: string;
}

export class ServiceGateway {
  private wss: WebSocketServer | null = null;
  private closeStack: () => void = () => {};
  private policy = new PolicyLoader();
  private pasTracker?: PowerAccumulationTracker;
  private pasThreshold = 100;
  private myPublicKey: string;
  private sessionMgr: SessionManager;
  private cfg: LatticeNodeYaml | null;
  private distributedMesh: boolean;
  private chain: NodeChainConfig | null;
  private resolver: LpGatewayResolver;
  private nodeLabel: string | undefined;
  private readonly journal: ActionJournal;
  private readonly ingress = new OverlayIngressLimiter(overlayIngressLimitsFromEnv());
  private readonly issuerGrants: ReadonlyMap<string, GatewayIssuerGrant>;
  private readonly issuerCertificateCache = new IssuerCertificateCache();
  private failures = 0;
  private readonly replayStore: ReplayStore;
  private readonly ownsReplayStore: boolean;
  private readonly backendResponseTimeoutMs: number;
  private readonly backendHttpAgent: http.Agent;
  private readonly backendHttpsAgent: https.Agent;
  /** Active outbound connections to relay rendezvous points (hidden mode). */
  private rendezvousConnections: WebSocket[] = [];
  /** Whether we're in hidden (outbound-only) mode. */
  private hiddenMode: boolean = false;
  /** Heartbeat timers for rendezvous connections. */
  private heartbeatTimers: ReturnType<typeof setInterval>[] = [];
  /** Deferred retries must be cancelled when a replica is drained. */
  private reconnectTimers: ReturnType<typeof setTimeout>[] = [];
  private announceTimer: ReturnType<typeof setTimeout> | undefined;
  private closed = false;
  private readonly nodeCrypto: NodeCryptoBackend;
  private readonly e2eResponseContexts = new Map<string, GatewayE2eResponseContext>();
  private readonly onionDirectRequests = new Set<string>();
  private hpkeFailures = 0;
  private readonly hiddenOnionCircuits: OnionCircuitClient[] = [];

  setPASTracker(tracker: PowerAccumulationTracker, threshold = 100): void {
    this.pasTracker = tracker;
    this.pasThreshold = threshold;
  }

  private checkPASAndMaybePause(agent: string): void {
    if (!this.pasTracker) return;
    const score = this.pasTracker.getScore(agent);
    if (score && score.score >= this.pasThreshold * 2) {
      controlBus.pauseAgent(agent);
    }
  }

  constructor(
    private serviceAddress: string,
    private targetHttpBase: string,
    portOrOpts?: number | ServiceGatewayOptions,
    maybeOpts?: ServiceGatewayOptions,
  ) {
    let portInput: number | undefined;
    let opts: ServiceGatewayOptions = {};
    if (typeof portOrOpts === 'number' || portOrOpts === undefined) {
      portInput = portOrOpts as number | undefined;
      opts = maybeOpts ?? {};
    } else {
      opts = portOrOpts;
      portInput = opts.port;
    }
    this.ownsReplayStore = !opts.replayStore;
    this.replayStore = opts.replayStore ?? replayStoreFromEnv();
    this.backendResponseTimeoutMs = backendResponseTimeoutFromEnv();
    const backendMaxSockets = backendMaxSocketsFromEnv();
    this.backendHttpAgent = new http.Agent({ keepAlive: true, maxSockets: backendMaxSockets, maxFreeSockets: Math.min(256, backendMaxSockets) });
    this.backendHttpsAgent = new https.Agent({ keepAlive: true, maxSockets: backendMaxSockets, maxFreeSockets: Math.min(256, backendMaxSockets) });
    this.journal = new ActionJournal(logPath(), actionJournalOptionsFromEnv());

    const cfgFromDisk = opts.nodeConfig !== undefined ? opts.nodeConfig : loadNodeConfig();
    this.cfg = cfgFromDisk;
    this.nodeCrypto = createNodeCryptoBackend(cfgFromDisk?.crypto);
    this.issuerGrants = new Map(resolveGatewayIssuerGrants(cfgFromDisk).map(grant => [grant.issuer_id, grant]));
    this.distributedMesh = distributedMeshEffective(cfgFromDisk);
    assertOnionOverlayRequired(cfgFromDisk, this.distributedMesh);
    this.nodeLabel = requireDistributedNodeId(cfgFromDisk, this.distributedMesh);
    this.chain = resolveNodeChainConfig(cfgFromDisk);
    this.resolver = new LpGatewayResolver(cfgFromDisk ?? null, this.chain);

    const gwKeyPair = getOrCreateOverlayKeyPair();
    this.myPublicKey = gwKeyPair.publicKey;
    this.sessionMgr = new SessionManager('gateway', gwKeyPair.privateKey, undefined, sessionMaxEntriesFromEnv());

    const gatewayMode = resolveGatewayMode(cfgFromDisk);
    this.hiddenMode = gatewayMode === 'hidden';

    if (this.hiddenMode) {
      // Hidden mode: dial outbound to rendezvous relays instead of listening
      const rendezvousRelays = resolveRendezvousRelays(cfgFromDisk);
      assertOnionWebSocketUrls(cfgFromDisk, rendezvousRelays.map(relay => relay.url));
      const hiddenAddr = resolveHiddenServiceAddress(cfgFromDisk) ?? serviceAddress;
      console.log(
        chalk.green('[Gateway]') +
          ` ${hiddenAddr} starting in HIDDEN mode → rendezvous with ${rendezvousRelays.length} relay(s)`,
      );
      if (onionOverlayEffective(cfgFromDisk)) {
        this.startHiddenOnionMode(rendezvousRelays, hiddenAddr);
      } else {
        this.startHiddenMode(rendezvousRelays, hiddenAddr, cfgFromDisk);
      }
      void this.announceFederation(cfgFromDisk, hiddenAddr, []);
    } else {
      // Public mode: bind inbound WebSocket port
      const defaultPort =
        cfgFromDisk?.bind?.gateway ?
          parseBindHostPort(cfgFromDisk.bind.gateway, '127.0.0.1', portInput ?? 8889).port
        : (portInput ?? 8889);

      const { host: bindHost, port: bindPort } = parseBindHostPort(
        cfgFromDisk?.bind?.gateway ?? opts.bindHostPort,
        '127.0.0.1',
        defaultPort,
      );
      assertOnionListenerTls(cfgFromDisk, bindHost, 'gateway');

      const bound = bindOverlayWebSocketServer(
        bindHost,
        bindPort,
        cfgFromDisk?.tls,
        undefined,
        (req, res) => {
          if (serveCellStatus(req, res, 'gateway', () => ({
            ...this.ingress.snapshot(),
            residentPeers: this.rendezvousConnections.length,
            failures: this.failures,
            hpkeFailures: this.hpkeFailures,
            issuerCertificateCacheEntries: this.issuerCertificateCache.snapshot().entries,
            issuerCertificateCacheHits: this.issuerCertificateCache.snapshot().hits,
            issuerCertificateCacheMisses: this.issuerCertificateCache.snapshot().misses,
          }))) return;
          res.writeHead(404, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: 'Not found' }));
        },
      );
      this.wss = bound.wss;
      this.closeStack = bound.close;

      this.wss.on('connection', (ws) => {
        ws.on('message', (data) => this.handleMessage(ws, data.toString()));
      });

      bound.wss.once('listening', () => {
        const scheme =
          cfgFromDisk?.tls?.certFile?.trim() && cfgFromDisk?.tls?.keyFile?.trim() ? 'wss' : 'ws';
        const endpoint = cfgFromDisk?.public?.gateway ?? `${scheme}://${bindHost}:${bindPort}`;
        console.log(
          chalk.green('[Gateway]') +
            ` ${serviceAddress} listening on ${scheme}://${bindHost}:${bindPort} -> routing to ${targetHttpBase}`,
        );
        // Announce to federation registries if configured
        const fedUrls = resolveFederationUrls(cfgFromDisk);
        if (fedUrls.length) {
          void this.announceFederation(cfgFromDisk, serviceAddress, [endpoint]);
        }
      });
      bound.wss.once('error', e => console.error(chalk.red('[Gateway] listen'), e.message));
    }
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    this.policy.dispose();
    void this.journal.close().catch(e => console.error(chalk.red('[Gateway] journal close'), String(e)));
    this.closeStack();
    for (const t of this.heartbeatTimers) clearInterval(t);
    this.heartbeatTimers = [];
    for (const t of this.reconnectTimers) clearTimeout(t);
    this.reconnectTimers = [];
    if (this.announceTimer) clearTimeout(this.announceTimer);
    this.announceTimer = undefined;
    for (const ws of this.rendezvousConnections) {
      if (ws.readyState === WebSocket.OPEN) ws.close();
    }
    this.rendezvousConnections = [];
    for (const circuit of this.hiddenOnionCircuits.splice(0)) circuit.destroy();
    this.backendHttpAgent.destroy();
    this.backendHttpsAgent.destroy();
    if (this.ownsReplayStore) (this.replayStore as { close?: () => void }).close?.();
  }

  // ─── Hidden-mode internals ────────────────────────────────────────────────

  private startHiddenOnionMode(relayTargets: UpstreamRelay[], serviceAddress: string): void {
    for (const target of relayTargets) {
      if (!target.label) throw new Error('Onion hidden Gateway requires labeled rendezvous relays');
      void this.runHiddenOnionWorker(target, serviceAddress, 0);
    }
  }

  private async runHiddenOnionWorker(
    target: UpstreamRelay,
    serviceAddress: string,
    attempt: number,
  ): Promise<void> {
    if (this.closed || !target.label) return;
    let circuit: OnionCircuitClient | undefined;
    try {
      const directory = readRoutingCacheFile(this.cfg, { requireLocalSig: true });
      if (!directory) throw new Error('Authenticated relay directory is missing');
      const candidates = relayCandidatesFromRoutingCache(directory);
      const targetCandidate = candidates.find(candidate => candidate.label === target.label);
      if (!targetCandidate || new URL(targetCandidate.endpoint).toString() !== new URL(target.url).toString()) {
        throw new Error('Rendezvous endpoint is not directory-authenticated');
      }
      const limits = resolveOnionCircuitConfig(this.cfg);
      const guards = new GuardSetStore(undefined, limits.guardLifetimeDays * 24 * 60 * 60_000)
        .loadOrSelect(candidates);
      const circuitPath = selectCircuitPath(candidates, {
        terminalLabel: target.label,
        guardLabels: guards,
        allowSingleOperatorLoopbackTests: limits.allowSingleOperatorLoopbackTests,
      });
      circuit = new OnionCircuitClient(
        circuitPath, this.nodeLabel!, 'gateway', this.cfg, this.nodeCrypto, limits,
      );
      await circuit.build();
      this.hiddenOnionCircuits.push(circuit);
      const fqdn = serviceAddress.replace(/^lp:\/\//, '').split('/')[0] ?? '';
      const encryptionKey = await this.nodeCrypto.currentKey('gateway-encryption');
      const token = hiddenRendezvousToken(encryptionKey.keyId, target.label, fqdn);
      await this.pollHiddenOnion(circuit, target, serviceAddress, token);
      if (!circuit.state.shouldRebuild()) return;
      throw new Error('Hidden Gateway circuit reached its reuse limit');
    } catch {
      circuit?.destroy('peer_failure');
      const index = circuit ? this.hiddenOnionCircuits.indexOf(circuit) : -1;
      if (index >= 0) this.hiddenOnionCircuits.splice(index, 1);
      if (this.closed) return;
      const delay = Math.min(30_000, 1_000 * Math.pow(2, Math.min(attempt, 5)));
      let retry: ReturnType<typeof setTimeout>;
      retry = setTimeout(() => {
        this.reconnectTimers = this.reconnectTimers.filter(timer => timer !== retry);
        void this.runHiddenOnionWorker(target, serviceAddress, attempt + 1);
      }, delay);
      retry.unref?.();
      this.reconnectTimers.push(retry);
    }
  }

  private async pollHiddenOnion(
    circuit: OnionCircuitClient,
    target: UpstreamRelay,
    serviceAddress: string,
    token: string,
  ): Promise<void> {
    if (this.closed || circuit.state.shouldRebuild()) return;
    const identity = await this.nodeCrypto.currentKey('identity');
    const poll = await createHiddenGatewayOperation(
      'hidden-poll', token, this.nodeLabel!, identity, this.nodeCrypto,
    );
    const raw = await circuit.request(Buffer.from(JSON.stringify(poll), 'utf8'));
    const result = JSON.parse(raw.toString('utf8')) as { request?: unknown };
    if (result.request) {
      const request = parseOverlayMessage(JSON.stringify(result.request));
      if (!request || request.type !== 'request' || !request.payload.e2e) throw new Error('Invalid rendezvous request');
      const response = await this.handleOnionDirectRequest(request);
      const responseOperation = await createHiddenGatewayOperation(
        'hidden-response',
        token,
        this.nodeLabel!,
        await this.nodeCrypto.currentKey('identity'),
        this.nodeCrypto,
        {
          request_id: request.id,
          response: {
            id: response.id,
            type: response.type,
            source: this.nodeLabel!,
            destination: 'rendezvous',
            payload: { e2e: response.payload.e2e },
            trace: [],
          },
        },
      );
      await circuit.request(Buffer.from(JSON.stringify(responseOperation), 'utf8'));
    }
    if (this.closed || circuit.state.shouldRebuild()) return;
    await new Promise<void>(resolve => {
      const timer = setTimeout(resolve, 250);
      timer.unref?.();
    });
    return this.pollHiddenOnion(circuit, target, serviceAddress, token);
  }

  private startHiddenMode(
    relayTargets: UpstreamRelay[],
    serviceAddress: string,
    cfg: LatticeNodeYaml | null,
  ): void {
    if (this.closed) return;
    for (const target of relayTargets) {
      if (this.distributedMesh && !target.label) {
        throw new Error('distributedMesh hidden gateways require labeled rendezvous relays');
      }
      this.connectToRendezvousRelay(target, serviceAddress, cfg, 0);
    }
  }

  private connectToRendezvousRelay(
    relayTarget: UpstreamRelay,
    serviceAddress: string,
    cfg: LatticeNodeYaml | null,
    attempt: number,
  ): void {
    if (this.closed) return;
    const tlsOpts = wsTlsClientOptions(cfg);
    const relayUrl = relayTarget.url;
    const ws = new WebSocket(relayUrl, undefined, { rejectUnauthorized: true, ...tlsOpts });
    this.rendezvousConnections.push(ws);

    ws.on('open', () => {
      void this.registerRendezvousConnection(ws, relayTarget, serviceAddress).catch((e: unknown) => {
        console.warn(chalk.yellow('[Gateway]') + ` Rendezvous identity failed (${relayUrl}): ${String(e)}`);
        ws.close();
      });
    });

    ws.on('message', (data) => {
      const raw = data.toString();
      const msg = parseOverlayMessage(raw);
      if (!msg) return;
      // register_ack is informational; all request frames are authenticated in
      // handleMessage before they can affect policy or a backend.
      if (msg.type === 'register_ack') return;
      this.handleMessage(ws, raw);
    });

    ws.on('close', () => {
      this.rendezvousConnections = this.rendezvousConnections.filter(c => c !== ws);
      if (this.closed) return;
      const delay = Math.min(30_000, 1_000 * Math.pow(2, Math.min(attempt, 5)));
      console.log(chalk.yellow('[Gateway]') + ` Rendezvous disconnected (${relayUrl}), retry in ${delay}ms`);
      let retry: ReturnType<typeof setTimeout>;
      retry = setTimeout(() => {
        this.reconnectTimers = this.reconnectTimers.filter(timer => timer !== retry);
        if (!this.closed) this.connectToRendezvousRelay(relayTarget, serviceAddress, cfg, attempt + 1);
      }, delay);
      this.reconnectTimers.push(retry);
    });

    ws.on('error', (e) => {
      console.warn(chalk.yellow('[Gateway]') + ` Rendezvous error (${relayUrl}): ${e.message}`);
    });
  }

  private async registerRendezvousConnection(
    ws: WebSocket,
    relayTarget: UpstreamRelay,
    serviceAddress: string,
  ): Promise<void> {
    const relayPub = this.distributedMesh
      ? await this.resolver.resolveRelayPubkey(relayTarget.label)
      : undefined;
    if (this.distributedMesh && !relayPub) throw new Error(`Could not resolve relay key for ${relayTarget.label}`);
    const signKey = this.relaySignMaterial(relayPub);
    console.log(chalk.green('[Gateway]') + ` Connected to rendezvous relay: ${relayTarget.url}`);

    const regMsg = signOverlayMessage(
        {
          id: `reg_${crypto.randomBytes(6).toString('hex')}`,
          type: 'register',
          source: serviceAddress,
          destination: 'relay',
          payload: {},
          trace: [],
          source_pubkey: this.myPublicKey,
          source_node_label: this.nodeLabel,
          source_node_role: 'gateway',
        },
      signKey,
    );
    ws.send(JSON.stringify(regMsg));

      // Keepalive heartbeat every 30 s
    let hb: ReturnType<typeof setInterval>;
    const stopHeartbeat = () => {
      clearInterval(hb);
      this.heartbeatTimers = this.heartbeatTimers.filter(timer => timer !== hb);
    };
    hb = setInterval(() => {
      if (ws.readyState !== WebSocket.OPEN) { stopHeartbeat(); return; }
      const heartbeat: OverlayMessage = {
          id: `hb_${crypto.randomBytes(4).toString('hex')}`,
          type: 'heartbeat',
          source: serviceAddress,
          destination: 'relay',
          payload: {},
          trace: [],
          source_pubkey: this.myPublicKey,
          source_node_label: this.nodeLabel,
          source_node_role: 'gateway',
      };
      ws.send(JSON.stringify(signOverlayMessage(heartbeat, signKey)));
    }, 30_000);
    this.heartbeatTimers.push(hb);
    // A reconnect must release its timer immediately; waiting for the next
    // interval tick would retain one array entry per historical connection.
    ws.once('close', stopHeartbeat);
  }

  /** Announce this gateway's lp:// address + endpoints to all configured federation registries. */
  private async announceFederation(
    cfg: LatticeNodeYaml | null,
    serviceAddress: string,
    gatewayEndpoints: string[],
  ): Promise<void> {
    if (this.closed) return;
    const fedUrls = resolveFederationUrls(cfg);
    if (!fedUrls.length) return;
    const fqdn = serviceAddress.replace(/^lp:\/\//, '').split('/')[0] ?? '';
    if (!fqdn.endsWith('.lattice') && !fqdn.endsWith('.coral') && !fqdn.endsWith('.reef')) return;
    const ttl = cfg?.gateway?.announceTtlSeconds ?? 300;
    const overlaySecret = loadCA().overlaySecret;
    const encryptionKey = await this.nodeCrypto.currentKey('gateway-encryption');
    const delivery = this.hiddenMode
      ? {
          mode: 'hidden' as const,
          rendezvous: resolveRendezvousRelays(cfg).map((relay) => ({
            nodeLabel: relay.label ?? '',
            endpoint: relay.url,
            token: hiddenRendezvousToken(encryptionKey.keyId, relay.label ?? relay.url, fqdn),
            expiresAt: new Date(Date.now() + ttl * 1000).toISOString(),
          })),
        }
      : { mode: 'public' as const };
    if (delivery.mode === 'hidden' && delivery.rendezvous.some(item => !item.nodeLabel)) return;
    // FQDNs to announce: the signed human alias + the canonical key-derived
    // `<id>.coral` identity address.
    const selfAuthFqdn = deriveSelfAuthAddress(this.myPublicKey);
    const fqdnsToAnnounce = fqdn.endsWith('.lattice') || fqdn.endsWith('.coral') || fqdn.endsWith('.reef')
      ? [fqdn, selfAuthFqdn]
      : [fqdn];
    for (const announceFqdn of fqdnsToAnnounce) {
      for (const replicaUrl of federationReplicaUrls(fedUrls, announceFqdn)) {
        postFederationAnnounce(
          replicaUrl,
          {
            version: 3,
            fqdn: announceFqdn,
            gatewayPubKeyB64: this.myPublicKey,
            gatewayEndpoints,
            gatewayNodeLabel: this.nodeLabel,
            gatewayEncryptionKeyId: encryptionKey.keyId,
            gatewayEncryptionPubKeyB64Url: encryptionKey.publicKey,
            hpkeSuite: LATTICE_HPKE_SUITE,
            delivery,
          },
          { ttlSeconds: ttl, announcerPubKey: this.myPublicKey, overlaySecret },
        ).catch(() => {});
      }
    }
    // Re-announce at half the TTL
    this.announceTimer = setTimeout(
      () => { void this.announceFederation(cfg, serviceAddress, gatewayEndpoints); },
      (ttl / 2) * 1000,
    );
    this.announceTimer.unref?.();
  }

  private relaySignMaterial(relayPub?: string): Buffer | string {
    if (!this.distributedMesh) return loadCA().overlaySecret;
    if (!relayPub) throw new Error('Missing relay pubkey in distributed mesh');
    return this.sessionMgr.getSessionKey(peerWireId(relayPub), relayPub);
  }

  private handleMessage(ws: WebSocket, data: string) {
    const frameBytes = Math.max(1, Buffer.byteLength(data, 'utf8'));
    const requestId = parseOverlayMessage(data)?.id;
    if (!this.ingress.tryAcquire(ws, frameBytes)) {
      ws.close(1013, 'overlay backpressure');
      return;
    }
    void this.handleMessageAsync(ws, data).catch(() => {
      this.failures++;
    }).finally(() => {
      if (requestId) this.e2eResponseContexts.delete(requestId);
      this.ingress.release(ws, frameBytes);
    });
  }

  private async handleMessageAsync(ws: WebSocket, data: string, onionDirect = false) {
    let msg = parseOverlayMessage(data);
    if (!msg || msg.type !== 'request') return;

    let relayPub: string | undefined;
    if (!onionDirect) {
      const relayIdentity = await validateDistributedPeer({
        distributedMesh: this.distributedMesh,
        cfg: this.cfg,
        chain: this.chain,
        msg,
        expectedRole: 'relay',
      });
      if (!relayIdentity.ok) {
        // Do not derive a reply key from an unauthenticated peer's claimed key.
        // In mesh mode a negative identity result is silent by design.
        if (!this.distributedMesh) await this.sendResponse(ws, msg, 401, { error: relayIdentity.error });
        return;
      }
      relayPub = relayIdentity.pubkey;
      const ok = verifyIncomingOverlayFromPeer({
        distributedMesh: this.distributedMesh,
        mgr: this.sessionMgr,
        overlaySecret: loadCA().overlaySecret,
        expectedPeerPubKeyB64: relayPub,
        msg,
      });
      if (!ok) {
        await this.sendResponse(ws, msg, 401, { error: 'Unauthenticated overlay request' }, relayPub);
        return;
      }
    }

    if (this.distributedMesh) {
      const envelope = parseHpkeEnvelope(msg.payload.e2e);
      if (!envelope || envelope.direction !== 'request' || envelope.request_id !== msg.id) {
        this.failures++;
        return;
      }
      try {
        const inner = parseE2eRequest(await this.nodeCrypto.hpkeOpen<unknown>(envelope.key_id, envelope));
        if (inner.request_id !== msg.id || inner.route_hash !== envelope.route_hash ||
            inner.destination !== this.serviceAddress) {
          throw new Error('E2E request binding mismatch');
        }
        this.e2eResponseContexts.set(msg.id, {
          requestId: msg.id,
          routeHash: inner.route_hash,
          responseKeyId: inner.response_key_id,
          responsePublicKey: inner.response_public_key,
          transportDestination: msg.source,
        });
        msg = {
          ...msg,
          source: inner.source,
          destination: inner.destination,
          payload: {
            method: inner.method,
            url: inner.url,
            headers: inner.headers,
            body: inner.body,
            agent_proof: inner.agent_proof,
          },
        };
      } catch {
        this.hpkeFailures++;
        this.failures++;
        return;
      }
    }

    msg.trace.push('gateway');
    const proofResult = await this.verifyAgentProof(msg);
    if (!proofResult.ok) {
      await this.sendResponse(ws, msg, proofResult.status ?? 401, { error: proofResult.error }, relayPub);
      return;
    }
    const agent = proofResult.agent;

    if (isRevoked(agent)) {
      if (!await this.audit(agent, 'request', 'deny', 'AGENT_REVOKED', ws, msg, relayPub)) return;
      await this.sendResponse(ws, msg, 403, { error: 'AGENT_REVOKED' }, relayPub);
      return;
    }

    const reqUrlStr = msg.payload.url || '/';
    const action = this.inferAction(msg.payload.method ?? 'GET', reqUrlStr);
    const check = proofResult.issuerCheck ?? this.policy.check(agent, this.serviceAddress, action);

    if (!check.allowed) {
      if (!await this.audit(agent, action, 'deny', check.reason, ws, msg, relayPub)) return;
      await this.sendResponse(ws, msg, 403, { error: 'Forbidden by Gateway Policy', reason: check.reason }, relayPub);
      return;
    }

    if (check.requires_approval) {
      if (!await this.audit(agent, action, 'require_human_approval', check.reason, ws, msg, relayPub)) return;
      await this.sendResponse(ws, msg, 202, { status: 'pending_approval' }, relayPub);
      return;
    }

    const action_id = actionIdForProof(msg.payload.agent_proof!);
    if (!await this.audit(agent, action, 'allow', check.reason, ws, msg, relayPub, { action_id })) return;
    this.checkPASAndMaybePause(agent);

    await this.forwardHttp(msg, ws, relayPub, action_id);
  }

  private async handleOnionDirectRequest(request: OverlayMessage): Promise<OverlayMessage> {
    let responseRaw: string | undefined;
    const collector = {
      readyState: WebSocket.OPEN,
      send: (value: string | Buffer) => { responseRaw = value.toString(); },
      close: () => {},
    } as unknown as WebSocket;
    this.onionDirectRequests.add(request.id);
    try {
      await this.handleMessageAsync(collector, JSON.stringify(request), true);
      const response = responseRaw ? parseOverlayMessage(responseRaw) : null;
      if (!response || response.type !== 'response' || response.id !== request.id || !response.payload.e2e) {
        throw new Error('Gateway did not produce an encrypted rendezvous response');
      }
      return response;
    } finally {
      this.onionDirectRequests.delete(request.id);
      this.e2eResponseContexts.delete(request.id);
    }
  }

  private forwardHttp(
    msg: OverlayMessage,
    ws: WebSocket,
    relayPub?: string,
    actionId?: string,
  ): Promise<void> {
    const backend = this.buildBackendRequest(msg, actionId);
    if (!backend) {
      void this.sendResponse(ws, msg, 400, { error: 'Invalid backend request' }, relayPub);
      return Promise.resolve();
    }
    return new Promise(resolve => {
      let settled = false;
      const finish = () => {
        if (settled) return false;
        settled = true;
        resolve();
        return true;
      };
      const failBackend = (error: Error) => {
        if (!finish()) return;
        this.failures++;
        void this.sendResponse(ws, msg, 502, { error: 'Backend error', detail: error.message }, relayPub);
      };
      try {
        const client = backend.options.protocol === 'https:' ? https : http;
        const agent = backend.options.protocol === 'https:' ? this.backendHttpsAgent : this.backendHttpAgent;
        const req = client.request({ ...backend.options, agent }, (res) => {
          const declaredLength = Number(res.headers['content-length'] ?? 0);
          if (Number.isFinite(declaredLength) && declaredLength > MAX_BACKEND_RESPONSE_BYTES) {
            failBackend(new Error('Backend response too large'));
            res.destroy();
            return;
          }
          const chunks: Buffer[] = [];
          let responseBytes = 0;
          res.on('data', d => {
            responseBytes += d.length;
            if (responseBytes > MAX_BACKEND_RESPONSE_BYTES) {
              failBackend(new Error('Backend response too large'));
              res.destroy();
              return;
            }
            chunks.push(d);
          });
          res.on('end', () => {
            if (settled) return;
            void (async () => {
              const bodyStr = Buffer.concat(chunks).toString('base64');
              await this.sendHttpResponse(
                ws,
                msg,
                res.statusCode ?? 502,
                responseHeaders(res.headers),
                bodyStr,
                relayPub,
              );
              finish();
            })().catch(error => {
              failBackend(error instanceof Error ? error : new Error(String(error)));
            });
          });
          res.on('aborted', () => failBackend(new Error('Backend response aborted')));
          res.on('error', error => failBackend(error instanceof Error ? error : new Error(String(error))));
        });

        req.setTimeout(this.backendResponseTimeoutMs, () => req.destroy(new Error('Backend response timeout')));
        req.on('error', err => failBackend(err));
        if (backend.body.length) req.write(backend.body);
        req.end();
      } catch (error) {
        failBackend(error instanceof Error ? error : new Error(String(error)));
      }
    });
  }

  private async verifyAgentProof(msg: OverlayMessage): Promise<{ ok: true; agent: string; issuerCheck?: { allowed: boolean; requires_approval: boolean; reason: string } } | { ok: false; error: string; status?: number }> {
    const proof = msg.payload.agent_proof;
    if (!proof) return { ok: false, error: 'Missing end-to-end agent proof' };
    let agent: string;
    try {
      agent = normalizeAgentName(proof.agent);
    } catch {
      return { ok: false, error: 'Invalid agent identity' };
    }
    if (msg.source !== agent) return { ok: false, error: 'Agent proof does not match overlay source' };
    if (isRevoked(agent)) return { ok: false, error: 'AGENT_REVOKED' };

    const timestampMs = new Date(proof.timestamp).getTime();
    if (!Number.isFinite(timestampMs) || Math.abs(Date.now() - timestampMs) > 5 * 60_000) {
      return { ok: false, error: 'Stale agent proof' };
    }
    const body = decodeBase64(msg.payload.body ?? '');
    if (!body || hashRequestBody(body) !== proof.body_hash) {
      return { ok: false, error: 'Invalid agent proof body hash' };
    }

    let issuerCheck: { allowed: boolean; requires_approval: boolean; reason: string } | undefined;
    if (this.policy.hasExplicitPolicy(agent)) {
      let policy: ReturnType<PolicyLoader['load']>;
      try {
        policy = this.policy.load(agent);
      } catch {
        return { ok: false, error: 'Unknown agent policy' };
      }
      const pinnedKey = policy.trusted_public_key === proof.public_key;
      const trustedCert = policy.trusted_issuer
        ? this.issuerCertificateCache.verify(proof.certificate, policy.trusted_issuer)
        : null;
      const issuerTrusted = Boolean(trustedCert && trustedCert.agent_id === policy.trusted_issuer?.subject && trustedCert.public_key === proof.public_key);
      if (!pinnedKey && !issuerTrusted) return { ok: false, error: 'Untrusted agent signing key' };
    } else {
      issuerCheck = this.issuerCheckForProof(proof, this.inferAction(msg.payload.method ?? 'GET', msg.payload.url ?? '/'));
      if (!issuerCheck) return { ok: false, error: 'Untrusted agent signing key' };
    }

    const signed = requestSignaturePayload({
      agent,
      method: msg.payload.method,
      host: proof.host,
      url: msg.payload.url,
      timestamp: proof.timestamp,
      bodyHash: proof.body_hash,
    });
    if (!verifySignature(signed, proof.signature, proof.public_key)) {
      return { ok: false, error: 'Invalid end-to-end agent signature' };
    }
    let nonceAccepted: boolean;
    try {
      // Gateway replicas share this namespace. Keep it distinct from Entry's
      // admission claim because both layers deliberately verify one request.
      nonceAccepted = await this.replayStore.claim(gatewayReplayKey(agent, proof.timestamp, proof.nonce), getReplayWindowMs());
    } catch {
      return { ok: false, error: 'REPLAY_STORE_UNAVAILABLE', status: 503 };
    }
    if (!nonceAccepted) {
      return { ok: false, error: 'REPLAY_DETECTED' };
    }
    return { ok: true, agent, issuerCheck };
  }

  private issuerCheckForProof(proof: NonNullable<OverlayMessage['payload']['agent_proof']>, action: string) {
    const issuerId = proof.certificate && typeof proof.certificate === 'object'
      ? (proof.certificate as { ca_cert_id?: unknown }).ca_cert_id
      : undefined;
    const grant = typeof issuerId === 'string' ? this.issuerGrants.get(issuerId) : undefined;
    if (!grant) return undefined;
    const cert = this.issuerCertificateCache.verify(proof.certificate, grant);
    const service = grant.services.find(candidate => candidate.address === this.serviceAddress && candidate.actions.includes(action));
    const capability = `${this.serviceAddress}:${action}`;
    if (!cert || !service || !cert.allowed_capability_classes.includes(capability) || cert.forbidden_capability_classes.includes(capability)) {
      return undefined;
    }
    return { allowed: true, requires_approval: false, reason: `Issuer ${grant.issuer_id} capability grant` };
  }

  private buildBackendRequest(msg: OverlayMessage, actionId?: string): { options: http.RequestOptions; body: Buffer } | null {
    const method = (msg.payload.method ?? 'GET').toUpperCase();
    if (!ALLOWED_BACKEND_METHODS.has(method)) return null;
    const rawUrl = msg.payload.url ?? '/';
    if (!rawUrl.startsWith('/') || rawUrl.startsWith('//') || /[\r\n]/.test(rawUrl)) return null;
    let reqUrl: URL;
    let base: URL;
    try {
      reqUrl = new URL(rawUrl, 'http://lattice.invalid');
      base = new URL(this.targetHttpBase);
      if (!['http:', 'https:'].includes(base.protocol)) return null;
    } catch {
      return null;
    }
    const body = decodeBase64(msg.payload.body ?? '');
    if (!body) return null;
    const headers: Record<string, string | string[]> = {};
    for (const [rawName, rawValue] of Object.entries(msg.payload.headers ?? {})) {
      const name = rawName.toLowerCase();
      if (!/^[a-z0-9-]{1,128}$/.test(name) || HOP_BY_HOP_HEADERS.has(name) || name.startsWith('x-lattice-')) continue;
      const values = Array.isArray(rawValue) ? rawValue : [String(rawValue)];
      const clean = values.filter(v => v.length <= 8_192 && !/[\r\n]/.test(v));
      if (clean.length) headers[name] = clean.length === 1 ? clean[0]! : clean;
    }
    headers.host = base.host;
    headers['content-length'] = String(body.length);
    // Same signed agent proof always produces the same key across Gateway
    // replicas. Backends must treat it as an idempotency key for unsafe calls.
    if (actionId) headers['x-lattice-action-id'] = actionId;
    return {
      options: {
        protocol: base.protocol,
        hostname: base.hostname,
        port: base.port || (base.protocol === 'https:' ? 443 : 80),
        path: reqUrl.pathname + reqUrl.search,
        method,
        headers,
      },
      body,
    };
  }

  private inferAction(method: string, reqUrl: string): string {
    try {
      const parsed = new URL(reqUrl.startsWith('http') ? reqUrl : `http://localhost${reqUrl}`);
      const path = parsed.pathname.slice(1);
      if (path) return path;
    } catch {}
    return { GET: 'read', POST: 'write', DELETE: 'delete', PUT: 'write', PATCH: 'write' }[method] ?? method.toLowerCase();
  }

  private async audit(
    agent: string,
    action: string,
    decision: string,
    reason: string,
    ws: WebSocket,
    req: OverlayMessage,
    trustedRelayPub?: string,
    extra?: object,
  ): Promise<boolean> {
    try {
      await this.journal.append({ timestamp: new Date().toISOString(), agent, resource: this.serviceAddress, action, decision, reason, ...extra });
      return true;
    } catch {
      this.failures++;
      await this.sendResponse(ws, req, 503, { error: 'AUDIT_UNAVAILABLE' }, trustedRelayPub);
      return false;
    }
  }

  private async sendResponse(
    ws: WebSocket,
    req: OverlayMessage,
    status: number,
    bodyObj: object,
    trustedRelayPub?: string,
  ): Promise<void> {
    await this.sendHttpResponse(
      ws,
      req,
      status,
      { 'content-type': 'application/json' },
      Buffer.from(JSON.stringify(bodyObj)).toString('base64'),
      trustedRelayPub,
    );
  }

  private async sendHttpResponse(
    ws: WebSocket,
    req: OverlayMessage,
    status: number,
    headers: Record<string, string | string[] | number>,
    body: string,
    trustedRelayPub?: string,
  ): Promise<void> {
    const relayPub = trustedRelayPub ?? req.source_pubkey;
    const e2eContext = this.e2eResponseContexts.get(req.id);
    let payload: OverlayMessage['payload'] = { status, headers, body };
    let source = this.serviceAddress;
    let destination = req.source;
    let trace = req.trace;
    if (e2eContext) {
      const identity = await this.nodeCrypto.currentKey('identity');
      const unsigned: E2eResponseUnsigned = {
        version: 1,
        request_id: e2eContext.requestId,
        route_hash: e2eContext.routeHash,
        status,
        headers,
        body,
        gateway_identity_key_id: identity.keyId,
        gateway_identity_public_key: identity.publicKey,
      };
      const signature = await this.nodeCrypto.signEd25519(
        identity.keyId,
        gatewayResponseSignaturePayload(unsigned),
      );
      const envelopeNow = Date.now();
      const createdAt = new Date(envelopeNow).toISOString();
      const e2e = await sealHpkeJson(
        e2eContext.responsePublicKey,
        {
          direction: 'response',
          keyId: e2eContext.responseKeyId,
          requestId: e2eContext.requestId,
          routeHash: e2eContext.routeHash,
          createdAt,
          expiresAt: new Date(envelopeNow + 5 * 60_000).toISOString(),
        },
        { ...unsigned, signature: signature.toString('base64url') },
      );
      payload = { e2e };
      source = this.nodeLabel ?? 'gateway';
      destination = e2eContext.transportDestination;
      trace = [];
      this.e2eResponseContexts.delete(req.id);
    }
    const unsigned: OverlayMessage = {
      id: req.id,
      type: 'response',
      source,
      destination,
      payload,
      trace,
      source_pubkey: this.myPublicKey,
      source_node_label: this.nodeLabel,
      source_node_role: 'gateway',
    };
    if (this.onionDirectRequests.has(req.id)) {
      if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(unsigned));
      return;
    }
    let res: OverlayMessage;
    try {
      res = signOverlayMessage(unsigned, this.relaySignMaterial(relayPub));
    } catch {
      return;
    }
    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(res));
  }
}

/** Stable cross-replica idempotency key, bound to the signed agent proof. */
export function actionIdForProof(proof: AgentProof): string {
  return `act_${crypto.createHash('sha256')
    .update('lattice-action-v1\0', 'utf8')
    .update(proof.agent, 'utf8')
    .update('\0', 'utf8')
    .update(proof.public_key, 'utf8')
    .update('\0', 'utf8')
    .update(proof.signature, 'utf8')
    .digest('hex')}`;
}

function decodeBase64(value: string): Buffer | null {
  if (value === '') return Buffer.alloc(0);
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) return null;
  try {
    return Buffer.from(value, 'base64');
  } catch {
    return null;
  }
}

function responseHeaders(headers: http.IncomingHttpHeaders): Record<string, string | string[] | number> {
  const out: Record<string, string | string[] | number> = {};
  let usedBytes = 0;
  for (const [rawName, value] of Object.entries(headers)) {
    if (value === undefined) continue;
    const name = rawName.toLowerCase();
    if (!/^[a-z0-9-]{1,128}$/.test(name) || HOP_BY_HOP_HEADERS.has(name) || /[\r\n]/.test(name)) continue;
    if (Array.isArray(value)) {
      const clean = value.filter(v => !/[\r\n]/.test(v)).slice(0, 16);
      const bytes = clean.reduce((sum, item) => sum + Buffer.byteLength(name) + Buffer.byteLength(item) + 4, 0);
      if (clean.length && usedBytes + bytes <= MAX_BACKEND_RESPONSE_HEADER_BYTES) {
        out[name] = clean;
        usedBytes += bytes;
      }
    } else if (typeof value === 'number' || !/[\r\n]/.test(value)) {
      const text = String(value);
      const bytes = Buffer.byteLength(name) + Buffer.byteLength(text) + 4;
      if (usedBytes + bytes <= MAX_BACKEND_RESPONSE_HEADER_BYTES) {
        out[name] = value;
        usedBytes += bytes;
      }
    }
  }
  return out;
}

function backendResponseTimeoutFromEnv(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.LATTICE_BACKEND_RESPONSE_TIMEOUT_MS;
  if (raw === undefined || raw.trim() === '') return DEFAULT_BACKEND_RESPONSE_TIMEOUT_MS;
  if (!/^[0-9]+$/.test(raw.trim())) throw new Error('LATTICE_BACKEND_RESPONSE_TIMEOUT_MS must be an integer');
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed) || parsed < 1_000 || parsed > 120_000) {
    throw new Error('LATTICE_BACKEND_RESPONSE_TIMEOUT_MS must be between 1000 and 120000');
  }
  return parsed;
}

/** Bound pooled backend sockets independently of public WebSocket connections. */
export function backendMaxSocketsFromEnv(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.LATTICE_BACKEND_MAX_SOCKETS;
  if (raw === undefined || raw.trim() === '') return DEFAULT_BACKEND_MAX_SOCKETS;
  if (!/^[0-9]+$/.test(raw.trim())) throw new Error('LATTICE_BACKEND_MAX_SOCKETS must be an integer');
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed) || parsed < 32 || parsed > 65_536) {
    throw new Error('LATTICE_BACKEND_MAX_SOCKETS must be between 32 and 65536');
  }
  return parsed;
}

function hiddenRendezvousToken(encryptionKeyId: string, relayLabel: string, fqdn: string): string {
  return crypto.createHmac('sha256', encryptionKeyId)
    .update(`${relayLabel}\0${fqdn}`, 'utf8')
    .digest('base64url');
}
