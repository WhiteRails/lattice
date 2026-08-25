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
} from './node-config';
import { LpGatewayResolver, LpRoutingNotFoundError } from './lp-resolver';
import { bindOverlayWebSocketServer, wsTlsClientOptions } from './ws-stack';
import { overlayPubkeysEqual, validateDistributedPeer } from './peer-identity';
import { fqdnFromLpAddress } from './routing-cache';
import { OverlayRpcPool, overlayRpcPoolOptionsFromEnv } from './overlay-rpc';
import { OverlayIngressLimiter, overlayIngressLimitsFromEnv } from './overlay-ingress';
import { rendezvousOrder } from './rendezvous';
import { serveCellStatus } from './node-metrics';
import { OverlayResponseMultiplexer } from './overlay-response-multiplexer';

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

  constructor(opts: RelayNodeOptions = {}) {
    const cfgFromDisk = opts.nodeConfig !== undefined ? opts.nodeConfig : loadNodeConfig();
    this.cfg = cfgFromDisk;
    this.distributedMesh = distributedMeshEffective(cfgFromDisk);
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

    this.chain = resolveNodeChainConfig(cfgFromDisk);
    this.resolver = new LpGatewayResolver(cfgFromDisk ?? null, this.chain);
    this.gatewayPool = new OverlayRpcPool({ ...overlayRpcPoolOptionsFromEnv(), wsOptions: wsTlsClientOptions(cfgFromDisk) });

    const bound = bindOverlayWebSocketServer(
      bindHost,
      bindPort,
      cfgFromDisk?.tls,
      undefined,
      (req, res) => {
        if (serveCellStatus(req, res, 'relay', () => ({
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
      ws.on('message', (data) => {
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
}
