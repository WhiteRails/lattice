import { WebSocketServer, WebSocket } from 'ws';
import * as http from 'http';
import * as crypto from 'crypto';
import { OverlayMessage, parseOverlayMessage, signOverlayMessage } from './message';
import { PolicyLoader } from './policy-loader';
import { appendLog, isRevoked, loadCA, getOrCreateOverlayKeyPair, normalizeAgentName } from './state';
import { SessionManager } from './session';
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
  resolveRendezvousRelays,
  resolveHiddenServiceAddress,
  resolveFederationUrls,
} from './node-config';
import { bindOverlayWebSocketServer, wsTlsClientOptions } from './ws-stack';
import { validateDistributedPeer } from './peer-identity';
import { postFederationAnnounce } from './federation-registry';
import { deriveSelfAuthAddress } from './self-auth';
import { LpGatewayResolver } from './lp-resolver';
import { hashRequestBody, requestSignaturePayload, verifySignature } from '../core/identity';
import { NonceStore, getReplayWindowMs } from './nonce-store';

const agentProofNonces = new NonceStore();
const ALLOWED_BACKEND_METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);
const HOP_BY_HOP_HEADERS = new Set([
  'connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade', 'host', 'content-length',
]);

export interface ServiceGatewayOptions {
  port?: number;
  bindHostPort?: string;
  nodeConfig?: LatticeNodeYaml | null;
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
  /** Active outbound connections to relay rendezvous points (hidden mode). */
  private rendezvousConnections: WebSocket[] = [];
  /** Whether we're in hidden (outbound-only) mode. */
  private hiddenMode: boolean = false;
  /** Heartbeat timers for rendezvous connections. */
  private heartbeatTimers: ReturnType<typeof setInterval>[] = [];

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
    this.resolver = new LpGatewayResolver(cfgFromDisk ?? null, this.chain);

    const gwKeyPair = getOrCreateOverlayKeyPair();
    this.myPublicKey = gwKeyPair.publicKey;
    this.sessionMgr = new SessionManager('gateway', gwKeyPair.privateKey);

    const gatewayMode = resolveGatewayMode(cfgFromDisk);
    this.hiddenMode = gatewayMode === 'hidden';

    if (this.hiddenMode) {
      // Hidden mode: dial outbound to rendezvous relays instead of listening
      const rendezvousRelays = resolveRendezvousRelays(cfgFromDisk);
      const hiddenAddr = resolveHiddenServiceAddress(cfgFromDisk) ?? serviceAddress;
      console.log(
        chalk.green('[Gateway]') +
          ` ${hiddenAddr} starting in HIDDEN mode → rendezvous with ${rendezvousRelays.length} relay(s)`,
      );
      this.startHiddenMode(rendezvousRelays, hiddenAddr, cfgFromDisk);
      this.announceFederation(cfgFromDisk, hiddenAddr, []);
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

      const bound = bindOverlayWebSocketServer(bindHost, bindPort, cfgFromDisk?.tls);
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
          this.announceFederation(cfgFromDisk, serviceAddress, [endpoint]);
        }
      });
      bound.wss.once('error', e => console.error(chalk.red('[Gateway] listen'), e.message));
    }
  }

  close(): void {
    this.closeStack();
    for (const t of this.heartbeatTimers) clearInterval(t);
    for (const ws of this.rendezvousConnections) {
      if (ws.readyState === WebSocket.OPEN) ws.close();
    }
    this.rendezvousConnections = [];
  }

  // ─── Hidden-mode internals ────────────────────────────────────────────────

  private startHiddenMode(
    relayTargets: UpstreamRelay[],
    serviceAddress: string,
    cfg: LatticeNodeYaml | null,
  ): void {
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
      const delay = Math.min(30_000, 1_000 * Math.pow(2, Math.min(attempt, 5)));
      console.log(chalk.yellow('[Gateway]') + ` Rendezvous disconnected (${relayUrl}), retry in ${delay}ms`);
      setTimeout(
        () => this.connectToRendezvousRelay(relayTarget, serviceAddress, cfg, attempt + 1),
        delay,
      );
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
    const hb = setInterval(() => {
      if (ws.readyState !== WebSocket.OPEN) { clearInterval(hb); return; }
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
  }

  /** Announce this gateway's lp:// address + endpoints to all configured federation registries. */
  private announceFederation(
    cfg: LatticeNodeYaml | null,
    serviceAddress: string,
    gatewayEndpoints: string[],
  ): void {
    const fedUrls = resolveFederationUrls(cfg);
    if (!fedUrls.length) return;
    const fqdn = serviceAddress.replace(/^lp:\/\//, '').split('/')[0] ?? '';
    if (!fqdn.endsWith('.lattice') && !fqdn.endsWith('.id')) return;
    const ttl = cfg?.gateway?.announceTtlSeconds ?? 300;
    const overlaySecret = loadCA().overlaySecret;
    // FQDNs to announce: the named .lattice address + the self-auth .id address
    const selfAuthFqdn = deriveSelfAuthAddress(this.myPublicKey);
    const fqdnsToAnnounce = fqdn.endsWith('.lattice')
      ? [fqdn, selfAuthFqdn]
      : [fqdn];
    for (const url of fedUrls) {
      for (const announceFqdn of fqdnsToAnnounce) {
        postFederationAnnounce(
          url,
          {
            version: 2,
            fqdn: announceFqdn,
            gatewayPubKeyB64: this.myPublicKey,
            gatewayEndpoints,
            gatewayNodeLabel: this.nodeLabel,
          },
          { ttlSeconds: ttl, announcerPubKey: this.myPublicKey, overlaySecret },
        ).catch(() => {});
      }
    }
    // Re-announce at half the TTL
    setTimeout(() => this.announceFederation(cfg, serviceAddress, gatewayEndpoints), (ttl / 2) * 1000).unref?.();
  }

  private relaySignMaterial(relayPub?: string): Buffer | string {
    if (!this.distributedMesh) return loadCA().overlaySecret;
    if (!relayPub) throw new Error('Missing relay pubkey in distributed mesh');
    return this.sessionMgr.getSessionKey(peerWireId(relayPub), relayPub);
  }

  private handleMessage(ws: WebSocket, data: string) {
    void this.handleMessageAsync(ws, data).catch((e: unknown) => {
      console.warn(chalk.yellow('[Gateway]') + ` Dropped invalid overlay frame: ${String(e)}`);
    });
  }

  private async handleMessageAsync(ws: WebSocket, data: string) {
    const msg = parseOverlayMessage(data);
    if (!msg || msg.type !== 'request') return;

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
      if (!this.distributedMesh) this.sendResponse(ws, msg, 401, { error: relayIdentity.error });
      return;
    }

    const ok = verifyIncomingOverlayFromPeer({
      distributedMesh: this.distributedMesh,
      mgr: this.sessionMgr,
      overlaySecret: loadCA().overlaySecret,
      expectedPeerPubKeyB64: relayIdentity.pubkey,
      msg,
    });
    if (!ok) {
      this.sendResponse(ws, msg, 401, { error: 'Unauthenticated overlay request' }, relayIdentity.pubkey);
      return;
    }

    msg.trace.push('gateway');
    const proofResult = this.verifyAgentProof(msg);
    if (!proofResult.ok) {
      this.sendResponse(ws, msg, 401, { error: proofResult.error }, relayIdentity.pubkey);
      return;
    }
    const agent = proofResult.agent;

    if (isRevoked(agent)) {
      this.log(agent, 'request', 'deny', 'AGENT_REVOKED');
      this.sendResponse(ws, msg, 403, { error: 'AGENT_REVOKED' }, relayIdentity.pubkey);
      return;
    }

    const reqUrlStr = msg.payload.url || '/';
    const action = this.inferAction(msg.payload.method ?? 'GET', reqUrlStr);
    const check = this.policy.check(agent, this.serviceAddress, action);

    if (!check.allowed) {
      this.log(agent, action, 'deny', check.reason);
      this.sendResponse(ws, msg, 403, { error: 'Forbidden by Gateway Policy', reason: check.reason }, relayIdentity.pubkey);
      return;
    }

    if (check.requires_approval) {
      this.log(agent, action, 'require_human_approval', check.reason);
      this.sendResponse(ws, msg, 202, { status: 'pending_approval' }, relayIdentity.pubkey);
      return;
    }

    this.checkPASAndMaybePause(agent);

    this.forwardHttp(msg, ws, action, check.reason, relayIdentity.pubkey);
  }

  private forwardHttp(
    msg: OverlayMessage,
    ws: WebSocket,
    action: string,
    reason: string,
    relayPub?: string,
  ) {
    const backend = this.buildBackendRequest(msg);
    if (!backend) {
      this.sendResponse(ws, msg, 400, { error: 'Invalid backend request' }, relayPub);
      return;
    }

    const req = http.request(backend.options, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', d => chunks.push(d));
      res.on('end', () => {
        const bodyStr = Buffer.concat(chunks).toString('base64');

        const action_id = `act_${crypto.randomBytes(6).toString('hex')}`;
        this.log(msg.source, action, 'allow', reason, { action_id });

        const outMsg = signOverlayMessage(
          {
            id: msg.id,
            type: 'response',
            source: this.serviceAddress,
            destination: msg.source,
            payload: { status: res.statusCode, headers: responseHeaders(res.headers), body: bodyStr },
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
      this.sendResponse(ws, msg, 502, { error: 'Backend error', detail: err.message }, relayPub);
    });

    if (backend.body.length) req.write(backend.body);
    req.end();
  }

  private verifyAgentProof(msg: OverlayMessage): { ok: true; agent: string } | { ok: false; error: string } {
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

    let policy: ReturnType<PolicyLoader['load']>;
    try {
      policy = this.policy.load(agent);
    } catch {
      return { ok: false, error: 'Unknown agent policy' };
    }
    if (!policy.trusted_public_key || policy.trusted_public_key !== proof.public_key) {
      return { ok: false, error: 'Untrusted agent signing key' };
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
    if (!agentProofNonces.add(`${agent}:${proof.timestamp}:${proof.nonce}`, getReplayWindowMs())) {
      return { ok: false, error: 'REPLAY_DETECTED' };
    }
    return { ok: true, agent };
  }

  private buildBackendRequest(msg: OverlayMessage): { options: http.RequestOptions; body: Buffer } | null {
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

  private log(agent: string, action: string, decision: string, reason: string, extra?: object) {
    appendLog({ timestamp: new Date().toISOString(), agent, resource: this.serviceAddress, action, decision, reason, ...extra });
  }

  private sendResponse(
    ws: WebSocket,
    req: OverlayMessage,
    status: number,
    bodyObj: object,
    trustedRelayPub?: string,
  ) {
    const relayPub = trustedRelayPub ?? req.source_pubkey;
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
    } catch {
      return;
    }
    ws.send(JSON.stringify(res));
  }
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
  for (const [rawName, value] of Object.entries(headers)) {
    if (value === undefined) continue;
    const name = rawName.toLowerCase();
    if (!/^[a-z0-9-]{1,128}$/.test(name) || HOP_BY_HOP_HEADERS.has(name) || /[\r\n]/.test(name)) continue;
    if (Array.isArray(value)) {
      const clean = value.filter(v => !/[\r\n]/.test(v)).slice(0, 16);
      if (clean.length) out[name] = clean;
    } else if (typeof value === 'number' || !/[\r\n]/.test(value)) {
      out[name] = value;
    }
  }
  return out;
}
