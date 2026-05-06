import { WebSocketServer, WebSocket } from 'ws';
import * as http from 'http';
import * as crypto from 'crypto';
import { OverlayMessage, signOverlayMessage } from './message';
import { PolicyLoader } from './policy-loader';
import { appendLog, isRevoked, loadCA, getOrCreateOverlayKeyPair } from './state';
import { SessionManager } from './session';
import chalk from 'chalk';
import { controlBus } from './agent-control';
import { PowerAccumulationTracker } from '../core/pas';
import { verifyIncomingOverlayFromPeer, peerWireId } from './overlay-sign-key';
import type { LatticeNodeYaml, NodeChainConfig } from './node-config';
import {
  distributedMeshEffective,
  loadNodeConfig,
  parseBindHostPort,
  requireDistributedNodeId,
  resolveNodeChainConfig,
} from './node-config';
import { bindOverlayWebSocketServer } from './ws-stack';
import { validateDistributedPeer } from './peer-identity';

export interface ServiceGatewayOptions {
  port?: number;
  bindHostPort?: string;
  nodeConfig?: LatticeNodeYaml | null;
}

export class ServiceGateway {
  private wss: WebSocketServer;
  private closeStack: () => void;
  private policy = new PolicyLoader();
  private pasTracker?: PowerAccumulationTracker;
  private pasThreshold = 100;
  private myPublicKey: string;
  private sessionMgr: SessionManager;
  private cfg: LatticeNodeYaml | null;
  private distributedMesh: boolean;
  private chain: NodeChainConfig | null;
  private nodeLabel: string | undefined;

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
      portInput = undefined;
    }

    const cfgFromDisk = opts.nodeConfig !== undefined ? opts.nodeConfig : loadNodeConfig();
    this.cfg = cfgFromDisk;
    this.distributedMesh = distributedMeshEffective(cfgFromDisk);
    this.nodeLabel = requireDistributedNodeId(cfgFromDisk, this.distributedMesh);
    this.chain = resolveNodeChainConfig(cfgFromDisk);

    const gwKeyPair = getOrCreateOverlayKeyPair();
    this.myPublicKey = gwKeyPair.publicKey;
    this.sessionMgr = new SessionManager('gateway', gwKeyPair.privateKey);

    const defaultPort =
      cfgFromDisk?.bind?.gateway ?
        parseBindHostPort(cfgFromDisk.bind.gateway, '127.0.0.1', portInput ?? 8889).port
      : (portInput ?? 8889);

    const { host: bindHost, port: bindPort } = parseBindHostPort(
      cfgFromDisk?.bind?.gateway ?? opts.bindHostPort,
      '127.0.0.1',
      defaultPort,
    );

    const bound = bindOverlayWebSocketServer(bindHost, bindPort, cfgFromDisk?.tls);
    this.wss = bound.wss;
    this.closeStack = bound.close;

    this.wss.on('connection', (ws) => {
      ws.on('message', (data) => this.handleMessage(ws, data.toString()));
    });

    bound.wss.once('listening', () => {
      const scheme =
        cfgFromDisk?.tls?.certFile?.trim() && cfgFromDisk?.tls?.keyFile?.trim() ? 'wss' : 'ws';
      console.log(
        chalk.green('[Gateway]') +
          ` ${serviceAddress} listening on ${scheme}://${bindHost}:${bindPort} -> routing to ${targetHttpBase}`,
      );
    });
    bound.wss.once('error', e => console.error(chalk.red('[Gateway] listen'), e.message));
  }

  close(): void {
    this.closeStack();
  }

  private relaySignMaterial(relayPub?: string): Buffer | string {
    if (!relayPub && this.distributedMesh) throw new Error('Missing relay pubkey in distributed mesh');
    if (!relayPub) return loadCA().overlaySecret;
    return this.sessionMgr.getSessionKey(peerWireId(relayPub), relayPub);
  }

  private handleMessage(ws: WebSocket, data: string) {
    void this.handleMessageAsync(ws, data);
  }

  private async handleMessageAsync(ws: WebSocket, data: string) {
    let msg: OverlayMessage;
    try {
      msg = JSON.parse(data);
    } catch {
      return;
    }

    const ok = verifyIncomingOverlayFromPeer({
      distributedMesh: this.distributedMesh,
      mgr: this.sessionMgr,
      overlaySecret: loadCA().overlaySecret,
      peerPubFromMessage: msg.source_pubkey,
      msg,
    });

    if (!ok) {
      this.sendResponse(ws, msg, 401, { error: 'Unauthenticated overlay request' });
      return;
    }

    const relayIdentity = await validateDistributedPeer({
      distributedMesh: this.distributedMesh,
      cfg: this.cfg,
      chain: this.chain,
      msg,
      expectedRole: 'relay',
    });
    if (!relayIdentity.ok) {
      this.sendResponse(ws, msg, 401, { error: relayIdentity.error });
      return;
    }

    msg.trace.push('gateway');
    const agent = msg.source;

    if (isRevoked(agent)) {
      this.log(agent, 'request', 'deny', 'AGENT_REVOKED');
      this.sendResponse(ws, msg, 403, { error: 'AGENT_REVOKED' });
      return;
    }

    const reqUrlStr = msg.payload.url || '/';
    const action = this.inferAction(msg.payload.method ?? 'GET', reqUrlStr);
    const check = this.policy.check(agent, this.serviceAddress, action);

    if (!check.allowed) {
      this.log(agent, action, 'deny', check.reason);
      this.sendResponse(ws, msg, 403, { error: 'Forbidden by Gateway Policy', reason: check.reason });
      return;
    }

    if (check.requires_approval) {
      this.log(agent, action, 'require_human_approval', check.reason);
      this.sendResponse(ws, msg, 202, { status: 'pending_approval' });
      return;
    }

    this.checkPASAndMaybePause(agent);

    this.forwardHttp(msg, ws, action, check.reason);
  }

  private forwardHttp(msg: OverlayMessage, ws: WebSocket, action: string, reason: string) {
    const reqUrl = new URL(msg.payload.url?.startsWith('http') ? msg.payload.url : `http://localhost${msg.payload.url}`);
    const base = new URL(this.targetHttpBase);

    const options = {
      hostname: base.hostname,
      port: base.port || 80,
      path: reqUrl.pathname + reqUrl.search,
      method: msg.payload.method,
      headers: msg.payload.headers,
    };

    const req = http.request(options, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', d => chunks.push(d));
      res.on('end', () => {
        const bodyStr = Buffer.concat(chunks).toString('base64');

        const action_id = `act_${crypto.randomBytes(6).toString('hex')}`;
        this.log(msg.source, action, 'allow', reason, { action_id });

        const relayPub = msg.source_pubkey;
        const outMsg = signOverlayMessage(
          {
            id: msg.id,
            type: 'response',
            source: this.serviceAddress,
            destination: msg.source,
            payload: { status: res.statusCode, headers: res.headers as any, body: bodyStr },
            trace: msg.trace,
            source_pubkey: this.myPublicKey,
            source_node_label: this.nodeLabel,
            source_node_role: 'gateway',
          },
          this.relaySignMaterial(relayPub),
        );
        ws.send(JSON.stringify(outMsg));
      });
    });

    req.on('error', (err) => {
      this.sendResponse(ws, msg, 502, { error: 'Backend error', detail: err.message });
    });

    if (msg.payload.body) req.write(Buffer.from(msg.payload.body, 'base64'));
    req.end();
  }

  private inferAction(method: string, reqUrl: string): string {
    try {
      const parsed = new URL(reqUrl.startsWith('http') ? reqUrl : `http://localhost${reqUrl}`);
      const path = parsed.pathname.slice(1);
      if (path) return path;
    } catch {}
    return { GET: 'read', POST: 'write', DELETE: 'delete', PUT: 'write', PATCH: 'write' }[method] ?? method.toLowerCase();
  }

  private log(agent: string, action: string, decision: string, reason: string, extra?: object) {
    appendLog({ timestamp: new Date().toISOString(), agent, resource: this.serviceAddress, action, decision, reason, ...extra });
  }

  private sendResponse(ws: WebSocket, req: OverlayMessage, status: number, bodyObj: object) {
    const relayPub = req.source_pubkey;
    const unsigned: OverlayMessage = {
      id: req.id,
      type: 'response',
      source: this.serviceAddress,
      destination: req.source,
      payload: {
        status,
        headers: { 'content-type': 'application/json' },
        body: Buffer.from(JSON.stringify(bodyObj)).toString('base64'),
      },
      trace: req.trace,
      source_pubkey: this.myPublicKey,
      source_node_label: this.nodeLabel,
      source_node_role: 'gateway',
    };
    let res: OverlayMessage;
    try {
      res = signOverlayMessage(unsigned, this.relaySignMaterial(relayPub));
    } catch (e) {
      if (this.distributedMesh) res = unsigned;
      else throw e;
    }
    ws.send(JSON.stringify(res));
  }
}
