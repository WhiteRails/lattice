import { WebSocketServer, WebSocket } from 'ws';
import * as crypto from 'crypto';
import { OverlayMessage, parseOverlayMessage, signOverlayMessage } from './message';
import { loadCA, getOrCreateOverlayKeyPair } from './state';
import { SessionManager, sessionMaxEntriesFromEnv } from './session';
import chalk from 'chalk';
import { chooseOverlaySignKey, verifyIncomingOverlayFromPeer } from './overlay-sign-key';
import type { LatticeNodeYaml, NodeChainConfig } from './node-config';
import {
  distributedMeshEffective,
  loadNodeConfig,
  parseBindHostPort,
  requireDistributedNodeId,
  resolveNodeChainConfig,
  assertOnionListenerTls,
  assertOnionOverlayRequired,
  onionOverlayEffective,
  resolveOnionCircuitConfig,
} from './node-config';
import { LpGatewayResolver, LpRoutingNotFoundError } from './lp-resolver';
import { bindOverlayWebSocketServer, wsTlsClientOptions } from './ws-stack';
import { overlayPubkeysEqual, resolveRegisteredNode, validateDistributedPeer } from './peer-identity';
import { fqdnFromLpAddress } from './routing-cache';
import { OverlayRpcClient, OverlayRpcPool, overlayRpcPoolOptionsFromEnv } from './overlay-rpc';
import { OverlayIngressLimiter, overlayIngressLimitsFromEnv } from './overlay-ingress';
import { rendezvousOrder } from './rendezvous';
import { serveCellStatus } from './node-metrics';
import { OverlayResponseMultiplexer } from './overlay-response-multiplexer';
import { createNodeCryptoBackend } from './node-crypto';
import { OnionRelayRuntime } from './onion-network';
import {
  HiddenRendezvousOperationSchema,
  verifyHiddenGatewayOperation,
} from './hidden-rendezvous';
import type { NodeKeyDescriptor } from './node-crypto';

export const DEFAULT_RELAY_PORT = 8888;

export interface RelayNodeOptions {
  port?: number;
  bindHostPort?: string;
  nodeConfig?: LatticeNodeYaml | null;
}

interface HiddenGatewayConnection {
  ws: WebSocket;
  pubkey: string;
  nodeLabel?: string;
  responses: OverlayResponseMultiplexer;
}

interface HiddenOnionBrokerState {
  gatewayLabel: string;
  requests: OverlayMessage[];
  awaiting: Set<string>;
  responses: Map<string, OverlayMessage>;
  waiters: Map<string, Array<(response?: OverlayMessage) => void>>;
  touchedAt: number;
}

export class RelayNode {
  private wss: WebSocketServer;
  private closeStack: () => void;
  private myPublicKey: string;
  private upstreamMgr: SessionManager;
  private downstreamMgr: SessionManager;
  private distributedMesh: boolean;
  private cfg: LatticeNodeYaml | null;
  private resolver: LpGatewayResolver;
  private chain: NodeChainConfig | null;
  private nodeLabel: string | undefined;
  private gatewayPool: OverlayRpcPool;
  private readonly ingress = new OverlayIngressLimiter(overlayIngressLimitsFromEnv());
  private gatewayFailures = 0;
  private invalidFrames = 0;
  /**
   * Hidden-service rendezvous table.
   * Key: fqdn (e.g. "echo.lattice")
   * Value: the outbound WebSocket the gateway dialled into us.
   */
  private hiddenGateways: Map<string, HiddenGatewayConnection> = new Map();
  private readonly onionRuntime?: OnionRelayRuntime;
  private readonly hiddenOnionBroker = new Map<string, HiddenOnionBrokerState>();
  private readonly hiddenProofNonces = new Map<string, number>();

  constructor(opts: RelayNodeOptions = {}) {
    const cfgFromDisk = opts.nodeConfig !== undefined ? opts.nodeConfig : loadNodeConfig();
    this.cfg = cfgFromDisk;
    this.distributedMesh = distributedMeshEffective(cfgFromDisk);
    assertOnionOverlayRequired(cfgFromDisk, this.distributedMesh);
    this.nodeLabel = requireDistributedNodeId(cfgFromDisk, this.distributedMesh);

    const relayKeyPair = getOrCreateOverlayKeyPair();
    this.myPublicKey = relayKeyPair.publicKey;
    this.upstreamMgr = new SessionManager('relay-upstream', relayKeyPair.privateKey, undefined, sessionMaxEntriesFromEnv());
    this.downstreamMgr = new SessionManager('relay-downstream', relayKeyPair.privateKey, undefined, sessionMaxEntriesFromEnv());

    const defaultPort =
      cfgFromDisk?.bind?.relay ?
        parseBindHostPort(cfgFromDisk.bind.relay, '127.0.0.1', opts.port ?? DEFAULT_RELAY_PORT).port
      : (opts.port ?? DEFAULT_RELAY_PORT);

    const { host: bindHost, port: bindPort } = parseBindHostPort(
      cfgFromDisk?.bind?.relay ?? opts.bindHostPort,
      '127.0.0.1',
      defaultPort,
    );
    assertOnionListenerTls(cfgFromDisk, bindHost, 'relay');

    this.chain = resolveNodeChainConfig(cfgFromDisk);
    this.resolver = new LpGatewayResolver(cfgFromDisk ?? null, this.chain);
    this.gatewayPool = new OverlayRpcPool({ ...overlayRpcPoolOptionsFromEnv(), wsOptions: wsTlsClientOptions(cfgFromDisk) });
    if (onionOverlayEffective(cfgFromDisk)) {
      this.onionRuntime = new OnionRelayRuntime(
        this.nodeLabel!,
        cfgFromDisk,
        createNodeCryptoBackend(cfgFromDisk?.crypto),
        payload => this.forwardOnionExit(payload),
      );
    }

    const bound = bindOverlayWebSocketServer(
      bindHost,
      bindPort,
      cfgFromDisk?.tls,
      undefined,
      (req, res) => {
        if (serveCellStatus(req, res, 'relay', () => ({
          onionCircuitsActive: this.onionRuntime?.snapshot().active,
          onionCircuitsBuilt: this.onionRuntime?.snapshot().built,
          onionCircuitsDestroyed: this.onionRuntime?.snapshot().destroyed,
          onionNtorFailures: this.onionRuntime?.snapshot().ntorFailures,
          onionReplayFailures: this.onionRuntime?.snapshot().replayFailures,
          onionInvalidTags: this.onionRuntime?.snapshot().invalidTags,
          onionPaddingBytes: this.onionRuntime?.snapshot().paddingBytes,
          ...this.ingress.snapshot(),
          outboundInFlight: this.gatewayPool.inFlight(),
          residentPeers: this.hiddenGateways.size,
          failures: this.gatewayFailures + this.invalidFrames,
        }))) return;
        res.writeHead(404, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'Not found' }));
      },
    );
    this.wss = bound.wss;
    this.closeStack = bound.close;

    this.wss.on('connection', (ws) => {
      ws.on('message', (data, isBinary) => {
        if (this.onionRuntime?.handles(data, isBinary)) {
          this.onionRuntime.handle(ws, data, isBinary);
          return;
        }
        const raw = data.toString();
        const frameBytes = Math.max(1, Buffer.byteLength(raw, 'utf8'));
        if (!this.ingress.tryAcquire(ws, frameBytes)) {
          ws.close(1013, 'overlay backpressure');
          return;
        }
        void this.handleMessage(ws, raw).catch((e: unknown) => {
          this.invalidFrames++;
        }).finally(() => this.ingress.release(ws, frameBytes));
      });
    });

    bound.wss.once('listening', () => {
      const scheme =
        cfgFromDisk?.tls?.certFile?.trim() && cfgFromDisk?.tls?.keyFile?.trim() ? 'wss' : 'ws';
      console.log(
        chalk.magenta('[RelayNode]') + ` Listening for overlay traffic on ${scheme}://${bindHost}:${bindPort}`,
      );
    });
    bound.wss.once('error', e => console.error(chalk.red('[RelayNode] listen'), e.message));
  }

  close(): void {
    this.gatewayPool.close();
    this.closeStack();
  }

  /** Called when a hidden gateway dials in and sends a 'register' message. */
  private async handleGatewayRegister(gatewayWs: WebSocket, msg: OverlayMessage): Promise<void> {
    const gatewayIdentity = await validateDistributedPeer({
      distributedMesh: this.distributedMesh,
      cfg: this.cfg,
      chain: this.chain,
      msg,
      expectedRole: 'gateway',
    });
    if (!gatewayIdentity.ok) return;
    const ok = verifyIncomingOverlayFromPeer({
      distributedMesh: this.distributedMesh,
      mgr: this.downstreamMgr,
      overlaySecret: loadCA().overlaySecret,
      expectedPeerPubKeyB64: gatewayIdentity.pubkey,
      msg,
    });
    if (!ok) return;

    let fqdn: string;
    try {
      fqdn = fqdnFromLpAddress(msg.source);
    } catch {
      console.warn(chalk.yellow('[RelayNode]') + ` Invalid hidden gateway address: ${msg.source}`);
      return;
    }

    // Hidden registration is never first-claim-wins: a route must already bind this
    // name to this exact gateway key before its socket is admitted.
    let route;
    try {
      route = await this.resolver.resolveDestination(`lp://${fqdn}`);
    } catch {
      return;
    }
    if (!overlayPubkeysEqual(route.gatewayPubKeyB64, msg.source_pubkey) ||
        (this.distributedMesh && (!route.gatewayNodeLabel || route.gatewayNodeLabel !== gatewayIdentity.label))) {
      console.warn(
        chalk.yellow('[RelayNode]') +
          ` Hidden gateway register rejected: authoritative route mismatch for ${fqdn}`,
      );
      return;
    }

    // Replace any stale connection for this service
    const existing = this.hiddenGateways.get(fqdn);
    if (existing && existing.ws !== gatewayWs && existing.ws.readyState === WebSocket.OPEN) {
      existing.ws.close();
    }
    const hiddenGateway: HiddenGatewayConnection = {
      ws: gatewayWs,
      pubkey: route.gatewayPubKeyB64,
      nodeLabel: route.gatewayNodeLabel,
      responses: new OverlayResponseMultiplexer(this.ingress.snapshot().maxInFlight, 30_000),
    };
    this.hiddenGateways.set(fqdn, hiddenGateway);
    console.log(chalk.magenta('[RelayNode]') + ` Hidden gateway registered: ${fqdn} (pubkey ${msg.source_pubkey?.slice(0, 12)}…)`);

    // One response dispatcher per Gateway connection. The old design added a
    // listener for every in-flight request, making delivery O(pending).
    gatewayWs.on('message', raw => {
      const response = parseOverlayMessage(raw.toString());
      if (response?.type === 'response') hiddenGateway.responses.resolve(response);
    });

    // Clean up on disconnect
    gatewayWs.once('close', () => {
      hiddenGateway.responses.close();
      if (this.hiddenGateways.get(fqdn)?.ws === gatewayWs) {
        this.hiddenGateways.delete(fqdn);
        console.log(chalk.magenta('[RelayNode]') + ` Hidden gateway disconnected: ${fqdn}`);
      }
    });

    // Send register_ack
    const ack: OverlayMessage = {
      id: `ack_${crypto.randomBytes(6).toString('hex')}`,
      type: 'register_ack',
      source: 'relay',
      destination: msg.source,
      payload: {},
      trace: [],
      source_pubkey: this.myPublicKey,
      source_node_label: this.nodeLabel,
      source_node_role: 'relay',
    };
    try {
      const signKey = chooseOverlaySignKey(
        this.downstreamMgr,
        this.distributedMesh,
        loadCA().overlaySecret,
        gatewayIdentity.pubkey,
      );
      if (gatewayWs.readyState === WebSocket.OPEN) gatewayWs.send(JSON.stringify(signOverlayMessage(ack, signKey)));
    } catch {}
  }

  private async handleMessage(clientWs: WebSocket, data: string) {
    const msg = parseOverlayMessage(data);
    if (!msg) return;

    // Hidden gateway rendezvous: gateway dials relay and registers itself
    if (msg.type === 'register') {
      await this.handleGatewayRegister(clientWs, msg);
      return;
    }

    // Keepalive heartbeats from hidden gateways — no response needed
    if (msg.type !== 'request') return;
    // Onion v1 Entry traffic is binary-only. Text requests remain available
    // solely for local JSON/HMAC mode and hidden Gateway registration traffic.
    if (onionOverlayEffective(this.cfg) && msg.source_node_role === 'entry') {
      clientWs.close(1003, 'onion-v1 requires binary cells');
      return;
    }

    const entryIdentity = await validateDistributedPeer({
      distributedMesh: this.distributedMesh,
      cfg: this.cfg,
      chain: this.chain,
      msg,
      expectedRole: 'entry',
    });
    if (!entryIdentity.ok) {
      return;
    }

    const entryPubOk = verifyIncomingOverlayFromPeer({
      distributedMesh: this.distributedMesh,
      mgr: this.upstreamMgr,
      overlaySecret: loadCA().overlaySecret,
      expectedPeerPubKeyB64: entryIdentity.pubkey,
      msg,
    });
    if (!entryPubOk) return;

    const entryPub = entryIdentity.pubkey;

    msg.trace.push('relay');

    let route;
    try {
      route = await this.resolver.resolveDestination(msg.destination);
    } catch (e: any) {
      const hint = e instanceof LpRoutingNotFoundError ? e.message : String(e?.message ?? e);
      this.sendError(clientWs, msg, hint);
      return;
    }

    if (this.distributedMesh && !route.gatewayNodeLabel) {
      this.sendError(clientWs, msg, `Missing gatewayNodeLabel for distributed route ${route.fqdn}`);
      return;
    }

    // Check if a hidden gateway has registered for this fqdn
    const hiddenGateway = this.hiddenGateways.get(route.fqdn);
    if (hiddenGateway && hiddenGateway.ws.readyState === WebSocket.OPEN) {
      try {
        const relaySignKeyDown = chooseOverlaySignKey(
          this.downstreamMgr,
          this.distributedMesh,
          loadCA().overlaySecret,
          route.gatewayPubKeyB64,
        );
        const downstreamMsg = signOverlayMessage(
          {
            ...msg,
            auth: undefined,
            source_pubkey: this.myPublicKey,
            source_node_label: this.nodeLabel,
            source_node_role: 'relay',
          },
          relaySignKeyDown,
        );

        // Register correlation before sending so a very fast peer cannot race
        // its response between send() and listener setup.
        const responsePromise = hiddenGateway.responses.waitFor(msg.id);
        try {
          hiddenGateway.ws.send(JSON.stringify(downstreamMsg));
        } catch (e: any) {
          hiddenGateway.responses.reject(msg.id, e instanceof Error ? e : new Error(String(e)));
        }

        let response: OverlayMessage;
        try {
          response = await responsePromise;
        } catch (e: any) {
          this.sendError(clientWs, msg, e?.message ?? 'hidden gateway error');
          return;
        }

        const hiddenIdentity = await validateDistributedPeer({
          distributedMesh: this.distributedMesh,
          cfg: this.cfg,
          chain: this.chain,
          msg: response,
          expectedRole: 'gateway',
          expectedLabel: hiddenGateway.nodeLabel,
          expectedPubKeyB64: hiddenGateway.pubkey,
        });
        if (!hiddenIdentity.ok) {
          this.sendError(clientWs, msg, 'Hidden gateway response identity failed');
          return;
        }
        const okGwPub = verifyIncomingOverlayFromPeer({
          distributedMesh: this.distributedMesh,
          mgr: this.downstreamMgr,
          overlaySecret: loadCA().overlaySecret,
          expectedPeerPubKeyB64: hiddenIdentity.pubkey,
          msg: response,
        });

        if (!okGwPub) {
          this.sendError(clientWs, msg, 'Hidden gateway response auth failed');
          return;
        }

        response.trace.push('relay');
        const upstreamSignKey = chooseOverlaySignKey(
          this.upstreamMgr,
          this.distributedMesh,
          loadCA().overlaySecret,
          entryPub,
        );
        const upstreamResponse = signOverlayMessage(
          {
            ...response,
            auth: undefined,
            source_pubkey: this.myPublicKey,
            source_node_label: this.nodeLabel,
            source_node_role: 'relay',
          },
          upstreamSignKey,
        );
        if (clientWs.readyState === WebSocket.OPEN) {
          clientWs.send(JSON.stringify(upstreamResponse));
        }
      } catch (e: any) {
        this.sendError(clientWs, msg, e?.message ?? 'hidden gateway routing failed');
      }
      return;
    }

    // Stable agent affinity keeps replay/deduplication state local to one
    // replica during normal operation and spreads independent principals over
    // the fleet without a centralized routing table.
    const gatewayEndpoints = rendezvousOrder(route.gatewayEndpoints, `${route.fqdn}\u0000${msg.source}`);
    const tryEndpoint = async (idx: number): Promise<void> => {
      if (idx >= gatewayEndpoints.length) {
        this.sendError(clientWs, msg, 'Gateway unreachable (all endpoints failed)');
        return;
      }

      const targetUrl = gatewayEndpoints[idx]!;
      try {
        const relaySignKeyDown = chooseOverlaySignKey(
          this.downstreamMgr,
          this.distributedMesh,
          loadCA().overlaySecret,
          route.gatewayPubKeyB64,
        );
        const downstreamMsg = signOverlayMessage(
          {
            ...msg,
            auth: undefined,
            source_pubkey: this.myPublicKey,
            source_node_label: this.nodeLabel,
            source_node_role: 'relay',
          },
          relaySignKeyDown,
        );
        const response = await this.gatewayPool.request(targetUrl, downstreamMsg);
        if (!response || response.type !== 'response') {
          throw new Error('Invalid gateway response');
        }

        const gwIdentity = await validateDistributedPeer({
          distributedMesh: this.distributedMesh,
          cfg: this.cfg,
          chain: this.chain,
          msg: response,
          expectedRole: 'gateway',
          expectedLabel: route.gatewayNodeLabel,
          expectedPubKeyB64: route.gatewayPubKeyB64,
        });
        if (!gwIdentity.ok) {
          throw new Error('Gateway response identity failed');
        }

        const okGwPub = verifyIncomingOverlayFromPeer({
          distributedMesh: this.distributedMesh,
          mgr: this.downstreamMgr,
          overlaySecret: loadCA().overlaySecret,
          expectedPeerPubKeyB64: gwIdentity.pubkey,
          msg: response,
        });
        if (!okGwPub) {
          throw new Error('Gateway response auth failed');
        }

        if (this.distributedMesh && !overlayPubkeysEqual(response.source_pubkey, route.gatewayPubKeyB64)) {
          throw new Error('Gateway response key mismatch');
        }

        response.trace.push('relay');

        try {
          const upstreamSignKey = chooseOverlaySignKey(
            this.upstreamMgr,
            this.distributedMesh,
            loadCA().overlaySecret,
            entryPub,
          );
          const upstreamResponse = signOverlayMessage(
            {
              ...response,
              auth: undefined,
              source_pubkey: this.myPublicKey,
              source_node_label: this.nodeLabel,
              source_node_role: 'relay',
            },
            upstreamSignKey,
          );
          if (clientWs.readyState === WebSocket.OPEN) {
            clientWs.send(JSON.stringify(upstreamResponse));
          }
        } catch {
          this.sendError(clientWs, msg, 'relay signing failed');
        }
      } catch {
        // Preserve failover without emitting an attacker-amplifiable line per
        // retry. Cell metrics expose the aggregate failure rate.
        this.gatewayFailures++;
        await tryEndpoint(idx + 1);
      }
    };

    await tryEndpoint(0);
  }

  private sendError(ws: WebSocket, req: OverlayMessage, error: string) {
    const entryPub = req.source_pubkey;
    if (this.distributedMesh && !entryPub) return;
    let signKey: Buffer | string;
    try {
      signKey = chooseOverlaySignKey(
        this.upstreamMgr,
        this.distributedMesh,
        loadCA().overlaySecret,
        entryPub,
      );
    } catch {
      return;
    }

    const res = signOverlayMessage(
      {
        id: req.id,
        type: 'response',
        source: 'relay',
        destination: req.source,
        payload: {
          status: 502,
          headers: { 'content-type': 'application/json' },
          body: Buffer.from(JSON.stringify({ error })).toString('base64'),
        },
        trace: [...req.trace],
        source_pubkey: this.myPublicKey,
        source_node_label: this.nodeLabel,
        source_node_role: 'relay',
      },
      signKey,
    );
    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(res));
  }

  private async forwardOnionExit(payload: Buffer): Promise<Buffer> {
    if (payload.length > 1024 * 1024) throw new Error('Onion exit payload too large');
    let input: {
      version?: unknown;
      gateway_endpoint?: unknown;
      gateway_node_label?: unknown;
      gateway_overlay_public_key?: unknown;
      request?: unknown;
    };
    try {
      input = JSON.parse(payload.toString('utf8'));
    } catch {
      throw new Error('Invalid onion exit JSON');
    }
    if (typeof input === 'object' && input !== null &&
        typeof (input as { mode?: unknown }).mode === 'string' &&
        String((input as { mode: string }).mode).startsWith('hidden-')) {
      return this.handleHiddenOnionRendezvous(input);
    }
    if (input.version !== 1 || typeof input.gateway_endpoint !== 'string' ||
        typeof input.gateway_node_label !== 'string' || typeof input.gateway_overlay_public_key !== 'string') {
      throw new Error('Invalid onion exit descriptor');
    }
    const request = parseOverlayMessage(JSON.stringify(input.request));
    if (!request || request.type !== 'request' || !request.payload.e2e ||
        Object.keys(request.payload).some(key => key !== 'e2e')) {
      throw new Error('Onion exit accepts only opaque HPKE requests');
    }
    const gateway = await resolveRegisteredNode(this.cfg, this.chain, input.gateway_node_label);
    if (!gateway?.active || (gateway.roleBitmask & 4) === 0 ||
        !overlayPubkeysEqual(gateway.overlayPubKeyB64, input.gateway_overlay_public_key)) {
      throw new Error('Onion exit Gateway registry mismatch');
    }
    const url = new URL(input.gateway_endpoint);
    const allowLoopback = resolveOnionCircuitConfig(this.cfg).allowInsecureLoopbackTests;
    const loopback = ['127.0.0.1', '::1', 'localhost'].includes(url.hostname.replace(/^\[|]$/g, '').toLowerCase());
    if (url.protocol !== 'wss:' && !(url.protocol === 'ws:' && allowLoopback && loopback)) {
      throw new Error('ONION_WSS_REQUIRED: Gateway delivery endpoint must use WSS');
    }
    const gatewayPin = gateway.tlsFingerprintSha256?.toLowerCase().replace(/^0x/, '');
    if (url.protocol === 'wss:' && !/^[a-f0-9]{64}$/.test(gatewayPin ?? '')) {
      throw new Error('ONION_TLS_PIN_REQUIRED: Gateway SPKI pin is not registered');
    }
    const relaySignKey = chooseOverlaySignKey(
      this.downstreamMgr,
      true,
      loadCA().overlaySecret,
      gateway.overlayPubKeyB64,
    );
    const downstream = signOverlayMessage({
      ...request,
      auth: undefined,
      source: this.nodeLabel!,
      destination: input.gateway_node_label,
      trace: [],
      source_pubkey: this.myPublicKey,
      source_node_label: this.nodeLabel,
      source_node_role: 'relay',
    }, relaySignKey);
    const client = new OverlayRpcClient(url.toString(), {
      ...overlayRpcPoolOptionsFromEnv(),
      wsOptions: wsTlsClientOptions(this.cfg, gatewayPin),
    });
    let response: OverlayMessage;
    try {
      response = await client.request(downstream);
    } finally {
      client.close();
    }
    const gatewayIdentity = await validateDistributedPeer({
      distributedMesh: true,
      cfg: this.cfg,
      chain: this.chain,
      msg: response,
      expectedRole: 'gateway',
      expectedLabel: input.gateway_node_label,
      expectedPubKeyB64: gateway.overlayPubKeyB64,
    });
    if (!gatewayIdentity.ok || !verifyIncomingOverlayFromPeer({
      distributedMesh: true,
      mgr: this.downstreamMgr,
      overlaySecret: loadCA().overlaySecret,
      expectedPeerPubKeyB64: gatewayIdentity.pubkey,
      msg: response,
    }) || !response.payload.e2e || Object.keys(response.payload).some(key => key !== 'e2e')) {
      throw new Error('Invalid encrypted Gateway response');
    }
    const upstream: OverlayMessage = {
      id: request.id,
      type: 'response',
      source: this.nodeLabel!,
      destination: request.source,
      payload: { e2e: response.payload.e2e },
      trace: [],
      source_node_label: this.nodeLabel,
      source_node_role: 'relay',
    };
    return Buffer.from(JSON.stringify(upstream), 'utf8');
  }

  private async handleHiddenOnionRendezvous(input: unknown): Promise<Buffer> {
    this.cleanupHiddenBroker();
    const operation = HiddenRendezvousOperationSchema.parse(input);
    let broker = this.hiddenOnionBroker.get(operation.token);
    if (operation.mode === 'hidden-submit') {
      const request = parseOverlayMessage(JSON.stringify(operation.request));
      if (!request || request.type !== 'request' || !request.payload.e2e ||
          Object.keys(request.payload).some(key => key !== 'e2e')) {
        throw new Error('Hidden rendezvous accepts only opaque HPKE requests');
      }
      if (!broker) {
        if (this.hiddenOnionBroker.size >= 10_000) throw new Error('Hidden rendezvous capacity reached');
        broker = {
          gatewayLabel: operation.gateway_label,
          requests: [], awaiting: new Set(), responses: new Map(), waiters: new Map(), touchedAt: Date.now(),
        };
        this.hiddenOnionBroker.set(operation.token, broker);
      }
      if (broker.gatewayLabel !== operation.gateway_label) throw new Error('Hidden rendezvous Gateway mismatch');
      if (broker.requests.length >= 128 || broker.awaiting.has(request.id) || broker.responses.has(request.id)) {
        throw new Error('Hidden rendezvous request capacity or duplicate id');
      }
      broker.requests.push(request);
      broker.awaiting.add(request.id);
      broker.touchedAt = Date.now();
      return Buffer.from(JSON.stringify({ version: 1, accepted: true, request_id: request.id }), 'utf8');
    }
    if (operation.mode === 'hidden-wait') {
      const response = broker?.responses.get(operation.request_id);
      if (response) {
        broker!.responses.delete(operation.request_id);
        broker!.awaiting.delete(operation.request_id);
        broker!.touchedAt = Date.now();
        return Buffer.from(JSON.stringify({ version: 1, response }), 'utf8');
      }
      if (!broker || !broker.awaiting.has(operation.request_id)) {
        return Buffer.from(JSON.stringify({ version: 1, empty: true }), 'utf8');
      }
      const waited = await new Promise<OverlayMessage | undefined>(resolve => {
        const waiters = broker!.waiters.get(operation.request_id) ?? [];
        let timer: ReturnType<typeof setTimeout>;
        const complete = (response?: OverlayMessage) => {
          clearTimeout(timer);
          resolve(response);
        };
        waiters.push(complete);
        broker!.waiters.set(operation.request_id, waiters);
        timer = setTimeout(() => {
          const remaining = (broker!.waiters.get(operation.request_id) ?? []).filter(waiter => waiter !== complete);
          if (remaining.length) broker!.waiters.set(operation.request_id, remaining);
          else broker!.waiters.delete(operation.request_id);
          resolve(undefined);
        }, 30_000);
        timer.unref?.();
      });
      return Buffer.from(JSON.stringify(waited ? { version: 1, response: waited } : { version: 1, empty: true }), 'utf8');
    }

    const registeredGateway = await resolveRegisteredNode(this.cfg, this.chain, operation.gateway_label);
    if (!registeredGateway?.active || (registeredGateway.roleBitmask & 4) === 0 || !registeredGateway.identityPubKeyB64) {
      throw new Error('Unregistered hidden Gateway');
    }
    const authenticated = verifyHiddenGatewayOperation(
      operation,
      relayIdentityDescriptor(registeredGateway.identityPubKeyB64),
    );
    this.claimHiddenProofNonce(authenticated.gateway_label, authenticated.nonce);
    if (!broker || broker.gatewayLabel !== authenticated.gateway_label) {
      return Buffer.from(JSON.stringify({ version: 1, empty: true }), 'utf8');
    }
    broker.touchedAt = Date.now();
    if (authenticated.mode === 'hidden-poll') {
      const request = broker.requests.shift();
      return Buffer.from(JSON.stringify(request ? { version: 1, request } : { version: 1, empty: true }), 'utf8');
    }
    const response = parseOverlayMessage(JSON.stringify(authenticated.response));
    if (!response || response.type !== 'response' || response.id !== authenticated.request_id ||
        !response.payload.e2e || Object.keys(response.payload).some(key => key !== 'e2e') ||
        !broker.awaiting.has(response.id)) {
      throw new Error('Invalid hidden Gateway response');
    }
    const waiter = broker.waiters.get(response.id)?.shift();
    if (waiter) {
      if (!broker.waiters.get(response.id)?.length) broker.waiters.delete(response.id);
      broker.awaiting.delete(response.id);
      waiter(response);
    } else {
      broker.responses.set(response.id, response);
    }
    return Buffer.from(JSON.stringify({ version: 1, accepted: true, request_id: response.id }), 'utf8');
  }

  private cleanupHiddenBroker(now = Date.now()): void {
    for (const [token, broker] of this.hiddenOnionBroker) {
      if (now - broker.touchedAt > 5 * 60_000) {
        for (const waiters of broker.waiters.values()) waiters.forEach(waiter => waiter(undefined));
        this.hiddenOnionBroker.delete(token);
      }
    }
    for (const [nonce, expires] of this.hiddenProofNonces) {
      if (expires <= now) this.hiddenProofNonces.delete(nonce);
    }
  }

  private claimHiddenProofNonce(label: string, nonce: string, now = Date.now()): void {
    const key = `${label}\0${nonce}`;
    if (this.hiddenProofNonces.has(key)) throw new Error('Replayed hidden Gateway proof');
    if (this.hiddenProofNonces.size >= 100_000) throw new Error('Hidden proof replay cache capacity reached');
    this.hiddenProofNonces.set(key, now + 30_000);
  }
}

function relayIdentityDescriptor(publicKey: string): NodeKeyDescriptor {
  const der = Buffer.from(publicKey, 'base64');
  return {
    version: 1,
    keyId: crypto.createHash('sha256').update(der).digest('hex'),
    purpose: 'identity', algorithm: 'ed25519', publicKey,
    createdAt: new Date(0).toISOString(), status: 'active',
  };
}
