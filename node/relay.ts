import { WebSocketServer, WebSocket } from 'ws';
import { OverlayMessage, signOverlayMessage } from './message';
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
      ws.on('message', (data) => void this.handleMessage(ws, data.toString()));
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

  private async handleMessage(clientWs: WebSocket, data: string) {
    let msg: OverlayMessage;
    try {
      msg = JSON.parse(data);
    } catch {
      return;
    }

    const entryPubOk = verifyIncomingOverlayFromPeer({
      distributedMesh: this.distributedMesh,
      mgr: this.upstreamMgr,
      overlaySecret: loadCA().overlaySecret,
      peerPubFromMessage: msg.source_pubkey,
      msg,
    });

    if (!entryPubOk) {
      this.sendError(clientWs, msg, 'Unauthenticated overlay request');
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
      this.sendError(clientWs, msg, entryIdentity.error);
      return;
    }

    const entryPub = msg.source_pubkey;

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

      gatewayWs.on('message', async (gwData) => {
        let response: OverlayMessage;
        try {
          response = JSON.parse(gwData.toString());
        } catch {
          gatewayWs.close();
          void tryEndpoint(idx + 1);
          return;
        }

        const okGwPub = verifyIncomingOverlayFromPeer({
          distributedMesh: this.distributedMesh,
          mgr: this.downstreamMgr,
          overlaySecret: loadCA().overlaySecret,
          peerPubFromMessage: response.source_pubkey,
          msg: response,
        });

        if (!okGwPub) {
          gatewayWs.close();
          void tryEndpoint(idx + 1);
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
          void tryEndpoint(idx + 1);
          return;
        }

        if (this.distributedMesh && !overlayPubkeysEqual(response.source_pubkey, route.gatewayPubKeyB64)) {
          gatewayWs.close();
          void tryEndpoint(idx + 1);
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
      });

      gatewayWs.on('error', () => {
        gatewayWs.close();
        void tryEndpoint(idx + 1);
      });
    };

    await tryEndpoint(0);
  }

  private sendError(ws: WebSocket, req: OverlayMessage, error: string) {
    const entryPub = req.source_pubkey;
    let signKey: Buffer | string;
    try {
      signKey = chooseOverlaySignKey(
        this.upstreamMgr,
        this.distributedMesh,
        loadCA().overlaySecret,
        entryPub,
      );
    } catch {
      if (this.distributedMesh) {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({
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
          } satisfies OverlayMessage));
        }
        return;
      }
      signKey = loadCA().overlaySecret;
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
