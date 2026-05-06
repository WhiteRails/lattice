import * as http from 'http';
import * as crypto from 'crypto';
import { WebSocket } from 'ws';
import { OverlayMessage, signOverlayMessage } from './message';
import { isRevoked, loadAgent, loadCA, getOrCreateOverlayKeyPair } from './state';
import { hashRequestBody, requestSignaturePayload, verifySignature } from '../core/identity';
import { SessionManager } from './session';
import chalk from 'chalk';
import { NonceStore, getReplayWindowMs } from './nonce-store';
import { chooseOverlaySignKey, verifyIncomingOverlayFromPeer } from './overlay-sign-key';
import type { LatticeNodeYaml, NodeChainConfig, UpstreamRelay } from './node-config';
import {
  distributedMeshEffective,
  loadNodeConfig,
  normalizeUpstreamRelays,
  parseBindHostPort,
  requireDistributedNodeId,
  resolveNodeChainConfig,
} from './node-config';
import { LpGatewayResolver } from './lp-resolver';
import { bindHttpListen, wsTlsClientOptions } from './ws-stack';
import { validateDistributedPeer } from './peer-identity';

const nonceStore = new NonceStore();

export const DEFAULT_ENTRY_PORT = 7777;

export interface EntryNodeOptions {
  port?: number;
  bindHostPort?: string;
  /** Fallback when no ~/.lattice/node.yaml */
  relayUrls?: string[];
  nodeConfig?: LatticeNodeYaml | null;
}

export class EntryNode {
  private httpClose: () => void;
  private relayTargets: UpstreamRelay[];
  private myPublicKey: string;
  private sessionMgr: SessionManager;
  private distributedMesh: boolean;
  private cfg: LatticeNodeYaml | null;
  private resolver: LpGatewayResolver;
  private chain: NodeChainConfig | null;
  private nodeLabel: string | undefined;

  constructor(opts: EntryNodeOptions = {}) {
    const cfgFromDisk = opts.nodeConfig !== undefined ? opts.nodeConfig : loadNodeConfig();
    this.cfg = cfgFromDisk;
    this.distributedMesh = distributedMeshEffective(cfgFromDisk);
    this.nodeLabel = requireDistributedNodeId(cfgFromDisk, this.distributedMesh);
    const kp = getOrCreateOverlayKeyPair();
    this.myPublicKey = kp.publicKey;
    this.sessionMgr = new SessionManager('entry', kp.privateKey);

    this.relayTargets = opts.relayUrls?.length
      ? normalizeUpstreamRelays({ ...(cfgFromDisk ?? {}), upstreamRelays: opts.relayUrls }, opts.relayUrls)
      : normalizeUpstreamRelays(cfgFromDisk, ['ws://127.0.0.1:8888']);

    if (this.distributedMesh) {
      const missing = this.relayTargets.find(r => !r.label);
      if (missing) throw new Error(`distributedMesh requires relay labels for upstream relay ${missing.url}`);
    }

    const defaultPort =
      cfgFromDisk?.bind?.entry ?
        parseBindHostPort(cfgFromDisk.bind.entry, '127.0.0.1', opts.port ?? DEFAULT_ENTRY_PORT).port
      : (opts.port ?? DEFAULT_ENTRY_PORT);
    const { host: bindHost, port: bindPort } = parseBindHostPort(
      cfgFromDisk?.bind?.entry ?? opts.bindHostPort,
      '127.0.0.1',
      defaultPort,
    );

    this.chain = resolveNodeChainConfig(cfgFromDisk);
    this.resolver = new LpGatewayResolver(cfgFromDisk ?? null, this.chain);

    const bound = bindHttpListen(
      (req, res) => this.handleHttp(req, res),
      bindHost,
      bindPort,
      cfgFromDisk?.tls,
    );
    this.httpClose = bound.close;

    console.log(chalk.dim(`  (listening on ${bindHost}:${bindPort})...`));

    bound.server.once('listening', () => {
      const scheme =
        cfgFromDisk?.tls?.certFile?.trim() && cfgFromDisk?.tls?.keyFile?.trim() ? 'https' : 'http';
      console.log(chalk.cyan('[EntryNode]') + ` Listening for agents on ${scheme}://${bindHost}:${bindPort}`);
    });

    bound.server.once('error', (e) => {
      console.error(chalk.red('[EntryNode] HTTP listen error'), e.message);
      process.exit(1);
    });

    console.log(chalk.dim(`  overlay relays (${this.distributedMesh ? 'distributed ECDH' : 'local HMAC'}): ${this.relayTargets.map(r => r.url).join(', ')}`));
  }

  close(): void {
    this.httpClose();
  }

  private handleHttp(req: http.IncomingMessage, res: http.ServerResponse) {
    const agent = this.agentName(req);
    if (isRevoked(agent)) {
      res.writeHead(403);
      res.end(JSON.stringify({ error: 'Agent revoked' }));
      return;
    }

    const host = (req.headers.host ?? '').split(':')[0];
    const resource = `lp://${host}`;

    const chunks: Buffer[] = [];
    req.on('data', d => chunks.push(d));
    req.on('end', () => {
      const rawBody = Buffer.concat(chunks);
      const identity = this.verifyAgentRequest(req, agent, rawBody);
      if (!identity.ok) {
        res.writeHead(identity.status, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: identity.error }));
        return;
      }

      const body = rawBody.toString('base64');

      const msg: OverlayMessage = {
          id: crypto.randomBytes(8).toString('hex'),
          type: 'request',
          source: agent,
          destination: resource,
          payload: {
            method: req.method,
            url: req.url,
            headers: req.headers as Record<string, string>,
            body,
          },
          trace: ['entry'],
          source_pubkey: this.myPublicKey,
          source_node_label: this.nodeLabel,
          source_node_role: 'entry',
        };

      console.log(chalk.cyan('[EntryNode]') + ` Routing ${req.method} ${req.url} -> ${resource} via Relay`);
      void this.forwardToRelayWithFailover(msg, res, 0);
    });
  }

  private async relayPubkeyFor(target: UpstreamRelay): Promise<string | undefined> {
    if (!this.distributedMesh) return undefined;
    const pk = await this.resolver.resolveRelayPubkey(target.label);
    if (!pk) throw new Error(`Could not resolve relay pubkey for label "${target.label}"`);
    return pk;
  }

  private async forwardToRelayWithFailover(msg: OverlayMessage, res: http.ServerResponse, urlIndex: number): Promise<void> {
    if (urlIndex >= this.relayTargets.length) {
      res.writeHead(502, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'All overlay relays unreachable' }));
      return;
    }

    const target = this.relayTargets[urlIndex]!;
    const url = target.url;
    let signedMsg: OverlayMessage;
    try {
      const relayPubkey = await this.relayPubkeyFor(target);
      const signKey = chooseOverlaySignKey(
        this.sessionMgr,
        this.distributedMesh,
        loadCA().overlaySecret,
        relayPubkey,
      );
      signedMsg = signOverlayMessage(msg, signKey);
    } catch (e: any) {
      console.error(chalk.red('[EntryNode]') + ` Relay ${url} identity failed: ${e?.message ?? e}`);
      await this.forwardToRelayWithFailover(msg, res, urlIndex + 1);
      return;
    }

    const tlsOpts = wsTlsClientOptions(this.cfg);
    const ws = new WebSocket(url, undefined, { rejectUnauthorized: true, ...tlsOpts });

    ws.on('open', () => {
      ws.send(JSON.stringify(signedMsg));
    });

    ws.on('message', (data) => void (async () => {
      let response: OverlayMessage;
      try {
        response = JSON.parse(data.toString());
      } catch {
        res.writeHead(502, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid overlay response' }));
        ws.close();
        return;
      }

      const peer = await validateDistributedPeer({
        distributedMesh: this.distributedMesh,
        cfg: this.cfg,
        chain: this.chain,
        msg: response,
        expectedRole: 'relay',
        expectedLabel: target.label,
      });
      if (!peer.ok) {
        res.writeHead(502, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: peer.error }));
        ws.close();
        return;
      }

      const ok = verifyIncomingOverlayFromPeer({
        distributedMesh: this.distributedMesh,
        mgr: this.sessionMgr,
        overlaySecret: loadCA().overlaySecret,
        peerPubFromMessage: response.source_pubkey,
        msg: response,
      });
      if (!ok) {
        res.writeHead(502, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthenticated overlay response' }));
        ws.close();
        return;
      }

      if (response.id === msg.id && response.type === 'response') {
        res.writeHead(response.payload.status ?? 502, response.payload.headers);
        if (response.payload.body) {
          res.end(Buffer.from(response.payload.body, 'base64'));
        } else {
          res.end();
        }
        ws.close();
      }
    })());

    ws.on('error', (err) => {
      console.error(chalk.red('[EntryNode]') + ` Relay ${url} failed: ${err.message}`);
      ws.close();
      void this.forwardToRelayWithFailover(msg, res, urlIndex + 1);
    });
  }

  private agentName(req: http.IncomingMessage): string {
    return (req.headers['x-lattice-agent'] as string) ?? process.env.LATTICE_AGENT ?? 'unknown';
  }

  private verifyAgentRequest(
    req: http.IncomingMessage,
    agent: string,
    body: Buffer,
  ): { ok: true } | { ok: false; status: number; error: string } {
    let agentState;
    try {
      agentState = loadAgent(agent);
    } catch {
      return { ok: false, status: 401, error: 'Unknown agent identity' };
    }

    const signature = singleHeader(req.headers['x-lattice-signature']);
    const timestamp = singleHeader(req.headers['x-lattice-timestamp']);
    if (!signature || !timestamp) {
      return { ok: false, status: 401, error: 'Missing Lattice agent signature' };
    }

    const ageMs = Math.abs(Date.now() - new Date(timestamp).getTime());
    if (!Number.isFinite(ageMs) || ageMs > 5 * 60_000) {
      return { ok: false, status: 401, error: 'Stale Lattice agent signature' };
    }

    const nonce = singleHeader(req.headers['x-lattice-nonce']);
    if (!nonce) {
      return { ok: false, status: 401, error: 'Missing x-lattice-nonce header' };
    }
    const compositeKey = `${timestamp}:${nonce}`;
    const replayWindow = getReplayWindowMs();
    if (!nonceStore.add(compositeKey, replayWindow)) {
      return { ok: false, status: 401, error: 'REPLAY_DETECTED' };
    }

    const payload = requestSignaturePayload({
      method: req.method,
      host: singleHeader(req.headers.host),
      url: req.url,
      timestamp,
      bodyHash: hashRequestBody(body),
    });

    const publicKey = agentState.publicKey ?? agentState.cert?.public_key;
    if (!publicKey || !verifySignature(payload, signature, publicKey)) {
      return { ok: false, status: 401, error: 'Invalid Lattice agent signature' };
    }

    return { ok: true };
  }
}

function singleHeader(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}
