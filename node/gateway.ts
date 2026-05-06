import { WebSocketServer, WebSocket } from 'ws';
import * as http from 'http';
import * as crypto from 'crypto';
import { OverlayMessage, signOverlayMessage, verifyOverlayMessage } from './message';
import { PolicyLoader } from './policy-loader';
import { appendLog, isRevoked, loadCA, getOrCreateOverlayKeyPair } from './state';
import { SessionManager } from './session';
import chalk from 'chalk';
import { controlBus } from './agent-control';
import { PowerAccumulationTracker } from '../core/pas';

export class ServiceGateway {
  private wss: WebSocketServer;
  private policy = new PolicyLoader();
  private pasTracker?: PowerAccumulationTracker;
  private pasThreshold = 100;
  private myPublicKey: string;
  private sessionMgr: SessionManager;

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
    private serviceAddress: string, // e.g. lp://echo.lattice
    private targetHttpBase: string, // e.g. http://127.0.0.1:9001
    port: number
  ) {
    const gwKeyPair = getOrCreateOverlayKeyPair();
    this.myPublicKey = gwKeyPair.publicKey;
    this.sessionMgr = new SessionManager('gateway', gwKeyPair.privateKey);

    this.wss = new WebSocketServer({ port, host: '127.0.0.1' });
    
    this.wss.on('connection', (ws) => {
      ws.on('message', (data) => this.handleMessage(ws, data.toString()));
    });

    console.log(chalk.green(`[Gateway]`) + ` ${serviceAddress} listening on port ${port} -> routing to ${targetHttpBase}`);
  }

  private handleMessage(ws: WebSocket, data: string) {
    let msg: OverlayMessage;
    try { msg = JSON.parse(data); } catch { return; }
    // Verify with per-peer session key if sender provided pubkey; fall back to shared secret
    const verifyKey = msg.source_pubkey
      ? this.sessionMgr.getSessionKey(msg.source, msg.source_pubkey)
      : loadCA().overlaySecret;
    if (!verifyOverlayMessage(msg, verifyKey)) {
      this.sendResponse(ws, {
        id: msg.id,
        type: 'response',
        source: this.serviceAddress,
        destination: msg.source,
        payload: {},
        trace: msg.trace ?? [],
      }, 401, { error: 'Unauthenticated overlay request' });
      return;
    }

    msg.trace.push('gateway');
    const agent = msg.source;

    // 0. Check revocation before any policy evaluation
    if (isRevoked(agent)) {
      this.log(agent, 'request', 'deny', 'AGENT_REVOKED');
      this.sendResponse(ws, msg, 403, { error: 'AGENT_REVOKED' });
      return;
    }

    // 1. Evaluate Policy at the Gateway!
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

    // 2. Check PAS score and pause agent if critically exceeded
    this.checkPASAndMaybePause(agent);

    // 3. Forward to actual HTTP backend
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
      headers: msg.payload.headers
    };

    const req = http.request(options, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', d => chunks.push(d));
      res.on('end', () => {
        const bodyStr = Buffer.concat(chunks).toString('base64');
        
        const action_id = `act_${crypto.randomBytes(6).toString('hex')}`;
        this.log(msg.source, action, 'allow', reason, { action_id });

        const outMsg = signOverlayMessage({
          id: msg.id,
          type: 'response',
          source: this.serviceAddress,
          destination: msg.source,
          payload: { status: res.statusCode, headers: res.headers as any, body: bodyStr },
          trace: msg.trace,
          source_pubkey: this.myPublicKey,
        }, this.signKey(msg.source, msg.source_pubkey));
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

  private signKey(peerSource: string, peerPubKey?: string): Buffer | string {
    if (peerPubKey) return this.sessionMgr.getSessionKey(peerSource, peerPubKey);
    return loadCA().overlaySecret;
  }

  private sendResponse(ws: WebSocket, req: OverlayMessage, status: number, bodyObj: object) {
    const res = signOverlayMessage({
      id: req.id, type: 'response', source: this.serviceAddress, destination: req.source,
      payload: { status, headers: { 'content-type': 'application/json' }, body: Buffer.from(JSON.stringify(bodyObj)).toString('base64') },
      trace: req.trace,
      source_pubkey: this.myPublicKey,
    }, this.signKey(req.source, req.source_pubkey));
    ws.send(JSON.stringify(res));
  }
}
