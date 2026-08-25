import { WebSocketServer, WebSocket } from 'ws';
import * as crypto from 'crypto';
import { OverlayMessage, parseOverlayMessage, signOverlayMessage } from './message';
import { loadCA, getOrCreateOverlayKeyPair } from './state';
import { SessionManager } from './session';
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

export const DEFAULT_RELAY_PORT = 8888;

export interface RelayNodeOptions {
  port?: number;
  bindHostPort?: string;
  nodeConfig?: LatticeNodeYaml | null;
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
  /**
   * Hidden-service rendezvous table.
   * Key: fqdn (e.g. "echo.lattice")
   * Value: the outbound WebSocket the gateway dialled into us.
   */
  private hiddenGateways: Map<string, { ws: WebSocket; pubkey: string; nodeLabel?: string }> = new Map();

  constructor(opts: RelayNodeOptions = {}) {
    const cfgFromDisk = opts.nodeConfig !== undefined ? opts.nodeConfig : loadNodeConfig();
    this.cfg = cfgFromDisk;
    this.distributedMesh = distributedMeshEffective(cfgFromDisk);
    this.nodeLabel = requireDistributedNodeId(cfgFromDisk, this.distributedMesh);

    const relayKeyPair = getOrCreateOverlayKeyPair();
    this.myPublicKey = relayKeyPair.publicKey;
    this.upstreamMgr = new SessionManager('relay-upstream', relayKeyPair.privateKey);
    this.downstreamMgr = new SessionManager('relay-downstream', relayKeyPair.privateKey);

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

    const bound = bindOverlayWebSocketServer(bindHost, bindPort, cfgFromDisk?.tls);
    this.wss = bound.wss;
    this.closeStack = bound.close;

    this.wss.on('connection', (ws) => {
      ws.on('message', (data) => {
        void this.handleMessage(ws, data.toString()).catch((e: unknown) => {
          console.warn(chalk.yellow('[RelayNode]') + ` Dropped invalid overlay frame: ${String(e)}`);
        });
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
    this.hiddenGateways.set(fqdn, { ws: gatewayWs, pubkey: route.gatewayPubKeyB64, nodeLabel: route.gatewayNodeLabel });
    console.log(chalk.magenta('[RelayNode]') + ` Hidden gateway registered: ${fqdn} (pubkey ${msg.source_pubkey?.slice(0, 12)}…)`);

    // Clean up on disconnect
    gatewayWs.once('close', () => {
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

    console.log(chalk.magenta('[RelayNode]') + ` Routing ${msg.id} -> ${msg.destination}`);

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

    const tlsOpts = wsTlsClientOptions(this.cfg);

    // Check if a hidden gateway has registered for this fqdn
    const hiddenGateway = this.hiddenGateways.get(route.fqdn);
    if (hiddenGateway && hiddenGateway.ws.readyState === WebSocket.OPEN) {
      console.log(chalk.magenta('[RelayNode]') + ` Routing ${msg.id} to hidden gateway: ${route.fqdn}`);
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

        hiddenGateway.ws.send(JSON.stringify(downstreamMsg));

        // Wait for the response matching our request id on the persistent connection
        const responsePromise = new Promise<OverlayMessage>((resolve, reject) => {
          const timeout = setTimeout(() => {
            hiddenGateway.ws.off('message', onMsg);
            reject(new Error('hidden gateway timeout'));
          }, 30_000);
          const onMsg = (gwData: import('ws').RawData) => {
            let parsed: OverlayMessage;
            try {
              parsed = parseOverlayMessage(gwData.toString())!;
            } catch {
              return; // ignore non-JSON frames, keep waiting
            }
            if (!parsed) return;
            // Only resolve for the response to our specific request
            if (parsed.id !== msg.id) return;
            clearTimeout(timeout);
            hiddenGateway.ws.off('message', onMsg);
            resolve(parsed);
          };
          hiddenGateway.ws.on('message', onMsg);
        });

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

    const tryEndpoint = async (idx: number): Promise<void> => {
      if (idx >= route.gatewayEndpoints.length) {
        this.sendError(clientWs, msg, 'Gateway unreachable (all endpoints failed)');
        return;
      }

      const targetUrl = route.gatewayEndpoints[idx]!;
      const gatewayWs = new WebSocket(targetUrl, undefined, { rejectUnauthorized: true, ...tlsOpts });

      gatewayWs.on('open', () => {
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
          gatewayWs.send(JSON.stringify(downstreamMsg));
        } catch (e: any) {
          this.sendError(clientWs, msg, e?.message ?? 'sign failed');
          gatewayWs.close();
        }
      });

      gatewayWs.on('message', (gwData) => {
        void (async () => {
        const response = parseOverlayMessage(gwData.toString());
        if (!response || response.type !== 'response') {
          gatewayWs.close();
          await tryEndpoint(idx + 1);
          return;
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
          gatewayWs.close();
          await tryEndpoint(idx + 1);
          return;
        }

        const okGwPub = verifyIncomingOverlayFromPeer({
          distributedMesh: this.distributedMesh,
          mgr: this.downstreamMgr,
          overlaySecret: loadCA().overlaySecret,
          expectedPeerPubKeyB64: gwIdentity.pubkey,
          msg: response,
        });
        if (!okGwPub) {
          gatewayWs.close();
          await tryEndpoint(idx + 1);
          return;
        }

        if (this.distributedMesh && !overlayPubkeysEqual(response.source_pubkey, route.gatewayPubKeyB64)) {
          gatewayWs.close();
          await tryEndpoint(idx + 1);
          return;
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
        gatewayWs.close();
        })().catch(() => {
          gatewayWs.close();
          void tryEndpoint(idx + 1).catch(() => {});
        });
      });

      gatewayWs.on('error', () => {
        gatewayWs.close();
        void tryEndpoint(idx + 1).catch(() => {});
      });
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
