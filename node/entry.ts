import * as http from 'http';
import * as crypto from 'crypto';
import { OverlayMessage, parseOverlayMessage, signOverlayMessage } from './message';
import { isRevoked, loadAgentPublicIdentity, loadCA, getOrCreateOverlayKeyPair, normalizeAgentName } from './state';
import { hashRequestBody, requestSignaturePayload, verifySignature } from '../core/identity';
import { SessionManager, sessionMaxEntriesFromEnv } from './session';
import chalk from 'chalk';
import { getReplayWindowMs } from './nonce-store';
import { replayStoreFromEnv, type ReplayStore } from './replay-store';
import { entryReplayKey } from './replay-keys';
import { chooseOverlaySignKey, verifyIncomingOverlayFromPeer } from './overlay-sign-key';
import type { LatticeNodeYaml, NodeChainConfig, UpstreamRelay } from './node-config';
import {
  distributedMeshEffective,
  loadNodeConfig,
  normalizeUpstreamRelays,
  parseBindHostPort,
  requireDistributedNodeId,
  resolveEntryTrustedAgentIssuers,
  resolveNodeChainConfig,
  assertOnionWebSocketUrls,
  assertOnionOverlayRequired,
  resolveOnionCircuitConfig,
} from './node-config';
import { LpGatewayResolver, type ResolvedGatewayRoute } from './lp-resolver';
import { bindHttpListen, wsTlsClientOptions } from './ws-stack';
import { validateDistributedPeer } from './peer-identity';
import { resolveRegisteredNode } from './peer-identity';
import { OverlayRpcPool, overlayRpcPoolOptionsFromEnv } from './overlay-rpc';
import { OverlayIngressLimiter, overlayIngressLimitsFromEnv } from './overlay-ingress';
import { serveCellStatus } from './node-metrics';
import type { AgentIssuerTrust } from '../core/issuer-trust';
import { IssuerCertificateCache } from './issuer-certificate-cache';
import {
  generateHpkeKeyPair,
  openHpkeJson,
  parseHpkeEnvelope,
  sealHpkeJson,
} from './hpke-envelope';
import { parseE2eResponse, verifyGatewayResponse } from './e2e-message';
import { GuardSetStore, relayCandidatesFromRoutingCache, selectCircuitPath } from './circuit-selector';
import { readRoutingCacheFile } from './routing-cache';
import { OnionCircuitClient } from './onion-network';
import { createNodeCryptoBackend, type NodeCryptoBackend } from './node-crypto';

export const DEFAULT_ENTRY_PORT = 7777;
const MAX_AGENT_REQUEST_BYTES = 512 * 1024;
const MAX_OVERLAY_HEADER_BYTES = 32 * 1024;
const MIN_ENTRY_REQUEST_RESERVATION_BYTES = 64 * 1024;
const MAX_PORTABLE_AGENT_CERTIFICATE_HEADER_BYTES = 16 * 1024;

export interface EntryNodeOptions {
  port?: number;
  bindHostPort?: string;
  /** Fallback when no ~/.lattice/node.yaml */
  relayUrls?: string[];
  nodeConfig?: LatticeNodeYaml | null;
  replayStore?: ReplayStore;
}

interface EntryE2eResponseContext {
  requestId: string;
  routeHash: string;
  privateKey: string;
  gatewayIdentityPublicKey: string;
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
  private relayPool: OverlayRpcPool;
  private replayStore: ReplayStore;
  private readonly ownsReplayStore: boolean;
  private readonly ingress = new OverlayIngressLimiter(overlayIngressLimitsFromEnv());
  private readonly trustedAgentIssuers: ReadonlyMap<string, AgentIssuerTrust>;
  private readonly issuerCertificateCache = new IssuerCertificateCache();
  private relayFailures = 0;
  private onionCircuit?: OnionCircuitClient;
  private readonly onionLimits: ReturnType<typeof resolveOnionCircuitConfig>;
  private readonly nodeCrypto: NodeCryptoBackend;
  private onionCircuitsBuilt = 0;
  private onionCircuitsDestroyed = 0;
  private tlsPinMismatches = 0;
  private hpkeFailures = 0;

  constructor(opts: EntryNodeOptions = {}) {
    this.ownsReplayStore = !opts.replayStore;
    this.replayStore = opts.replayStore ?? replayStoreFromEnv();
    const cfgFromDisk = opts.nodeConfig !== undefined ? opts.nodeConfig : loadNodeConfig();
    this.cfg = cfgFromDisk;
    const configuredIssuers = new Map(resolveEntryTrustedAgentIssuers(cfgFromDisk).map(issuer => [issuer.issuer_id, issuer]));
    // The cell's own CA is already an operator-approved issuer. This permits
    // portable identities across its Entry replicas without copying one agent
    // file to every process; an externally supplied config cannot override it.
    const localCa = loadCA();
    configuredIssuers.set(localCa.caId, { issuer_id: localCa.caId, public_key: localCa.publicKey });
    this.trustedAgentIssuers = configuredIssuers;
    this.distributedMesh = distributedMeshEffective(cfgFromDisk);
    assertOnionOverlayRequired(cfgFromDisk, this.distributedMesh);
    this.nodeLabel = requireDistributedNodeId(cfgFromDisk, this.distributedMesh);
    this.onionLimits = resolveOnionCircuitConfig(cfgFromDisk);
    this.nodeCrypto = createNodeCryptoBackend(cfgFromDisk?.crypto);
    const kp = getOrCreateOverlayKeyPair();
    this.myPublicKey = kp.publicKey;
    this.sessionMgr = new SessionManager('entry', kp.privateKey, undefined, sessionMaxEntriesFromEnv());

    this.relayTargets = opts.relayUrls?.length
      ? normalizeUpstreamRelays({ ...(cfgFromDisk ?? {}), upstreamRelays: opts.relayUrls }, opts.relayUrls)
      : normalizeUpstreamRelays(cfgFromDisk, ['ws://127.0.0.1:8888']);

    if (this.distributedMesh) {
      const missing = this.relayTargets.find(r => !r.label);
      if (missing) throw new Error(`distributedMesh requires relay labels for upstream relay ${missing.url}`);
    }
    assertOnionWebSocketUrls(cfgFromDisk, this.relayTargets.map(target => target.url));

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
    this.relayPool = new OverlayRpcPool({ ...overlayRpcPoolOptionsFromEnv(), wsOptions: wsTlsClientOptions(cfgFromDisk) });

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
    if (this.onionCircuit && this.onionCircuit.state.snapshot().state !== 'destroyed') {
      this.onionCircuit.destroy();
      this.onionCircuitsDestroyed++;
    }
    this.relayPool.close();
    this.httpClose();
    if (this.ownsReplayStore) (this.replayStore as { close?: () => void }).close?.();
  }

  private handleHttp(req: http.IncomingMessage, res: http.ServerResponse) {
    if (serveCellStatus(req, res, 'entry', () => ({
      ...this.ingress.snapshot(),
      outboundInFlight: this.relayPool.inFlight(),
      failures: this.relayFailures,
      onionCircuitsActive: this.onionCircuit?.state.snapshot().state === 'ready' ? 1 : 0,
      onionCircuitsBuilt: this.onionCircuitsBuilt,
      onionCircuitsDestroyed: this.onionCircuitsDestroyed,
      tlsPinMismatches: this.tlsPinMismatches,
      hpkeFailures: this.hpkeFailures,
      issuerCertificateCacheEntries: this.issuerCertificateCache.snapshot().entries,
      issuerCertificateCacheHits: this.issuerCertificateCache.snapshot().hits,
      issuerCertificateCacheMisses: this.issuerCertificateCache.snapshot().misses,
    }))) return;
    let agent: string;
    try {
      agent = this.agentName(req);
    } catch {
      res.writeHead(400, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'Invalid Lattice agent identity' }));
      return;
    }
    const reservationBytes = entryReservationBytes(req);
    if (!this.ingress.tryAcquire(req.socket, reservationBytes)) {
      res.writeHead(503, { 'content-type': 'application/json', 'retry-after': '1' });
      res.end(JSON.stringify({ error: 'ENTRY_BACKPRESSURE' }));
      return;
    }
    let released = false;
    const release = () => {
      if (released) return;
      released = true;
      this.ingress.release(req.socket, reservationBytes);
    };
    if (isRevoked(agent)) {
      res.writeHead(403);
      res.end(JSON.stringify({ error: 'Agent revoked' }));
      release();
      return;
    }

    const host = (req.headers.host ?? '').split(':')[0];
    const resource = `lp://${host}`;

    const chunks: Buffer[] = [];
    let bodyBytes = 0;
    let rejected = false;
    req.on('data', d => {
      bodyBytes += d.length;
      if (bodyBytes > MAX_AGENT_REQUEST_BYTES) {
        rejected = true;
        if (!res.headersSent) {
          res.writeHead(413, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: 'Request body too large' }));
        }
        release();
        return;
      }
      chunks.push(d);
    });
    req.on('error', () => {
      if (!res.headersSent) {
        res.writeHead(400, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid request body' }));
      }
      release();
    });
    req.on('end', () => {
      if (rejected) return;
      const rawBody = Buffer.concat(chunks);
      void this.handleCompletedRequest(req, res, agent, resource, rawBody).catch((error: unknown) => {
        this.relayFailures++;
        console.warn(chalk.yellow('[EntryNode]') + ` encrypted request failed: ${error instanceof Error ? error.message : 'unknown error'}`);
        if (!res.headersSent) {
          res.writeHead(503, { 'content-type': 'application/json' });
          res.end(JSON.stringify({ error: 'Entry request verification unavailable' }));
        }
      }).finally(release);
    });
  }

  private async handleCompletedRequest(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    agent: string,
    resource: string,
    rawBody: Buffer,
  ): Promise<void> {
    const identity = await this.verifyAgentRequest(req, agent, rawBody);
    if (!identity.ok) {
      res.writeHead(identity.status, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: identity.error }));
      return;
    }
    const requestId = crypto.randomBytes(16).toString('hex');
    let msg: OverlayMessage = {
      id: requestId,
      type: 'request',
      source: agent,
      destination: resource,
      payload: {
        method: req.method,
        url: req.url,
        headers: overlayHeaders(req.headers),
        body: rawBody.toString('base64'),
        agent_proof: identity.proof,
      },
      trace: ['entry'],
      source_pubkey: this.myPublicKey,
      source_node_label: this.nodeLabel,
      source_node_role: 'entry',
    };
    let responseContext: EntryE2eResponseContext | undefined;
    let resolvedRoute: ResolvedGatewayRoute | undefined;
    if (this.distributedMesh) {
      const route = await this.resolver.resolveDestination(resource);
      resolvedRoute = route;
      if (!route.gatewayEncryptionKeyId || !route.gatewayEncryptionPubKeyB64Url || !route.gatewayNodeLabel) {
        throw new Error('ROUTE_ENCRYPTION_REQUIRED: incomplete Gateway encryption route');
      }
      const gatewayNode = await resolveRegisteredNode(this.cfg, this.chain, route.gatewayNodeLabel);
      if (!gatewayNode?.active || !gatewayNode.identityPubKeyB64) {
        throw new Error('ROUTE_ENCRYPTION_REQUIRED: Gateway identity key is not registered');
      }
      const responseKey = await generateHpkeKeyPair();
      const envelopeNow = Date.now();
      const createdAt = new Date(envelopeNow).toISOString();
      const expiresAt = new Date(envelopeNow + 5 * 60_000).toISOString();
      const e2e = await sealHpkeJson(
        route.gatewayEncryptionPubKeyB64Url,
        {
          direction: 'request',
          keyId: route.gatewayEncryptionKeyId,
          requestId,
          routeHash: route.metadataHash,
          createdAt,
          expiresAt,
        },
        {
          version: 1,
          request_id: requestId,
          route_hash: route.metadataHash,
          source: agent,
          destination: resource,
          method: req.method ?? 'GET',
          url: req.url ?? '/',
          headers: overlayHeaders(req.headers),
          body: rawBody.toString('base64'),
          agent_proof: identity.proof,
          response_key_id: responseKey.keyId,
          response_public_key: responseKey.publicKey,
        },
      );
      msg = {
        ...msg,
        // The transport identity is the Entry node. Agent identity and request
        // metadata exist only inside the Gateway HPKE envelope.
        source: this.nodeLabel ?? 'entry',
        destination: route.gatewayNodeLabel,
        payload: { e2e },
        trace: [],
      };
      responseContext = {
        requestId,
        routeHash: route.metadataHash.toLowerCase(),
        privateKey: responseKey.privateKey,
        gatewayIdentityPublicKey: gatewayNode.identityPubKeyB64,
      };
    }
    if (this.distributedMesh) {
      await this.forwardViaOnion(msg, res, responseContext!, resolvedRoute!);
      return;
    }
    await this.forwardToRelayWithFailover(msg, res, 0, responseContext);
  }

  private async forwardViaOnion(
    msg: OverlayMessage,
    res: http.ServerResponse,
    responseContext: EntryE2eResponseContext,
    route: ResolvedGatewayRoute,
  ): Promise<void> {
    if (!route.gatewayNodeLabel) throw new Error('ROUTE_ENCRYPTION_REQUIRED: missing Gateway node label');
    if (route.delivery?.mode === 'hidden') {
      const descriptor = route.delivery.rendezvous.find(value => new Date(value.expiresAt).getTime() > Date.now());
      if (!descriptor) throw new Error('HIDDEN_RENDEZVOUS_UNAVAILABLE: no live descriptor');
      const circuit = await this.ensureOnionCircuit(descriptor.nodeLabel);
      if (new URL(circuit.path.terminal.endpoint).toString() !== new URL(descriptor.endpoint).toString()) {
        throw new Error('HIDDEN_RENDEZVOUS_MISMATCH: descriptor endpoint is not directory-authenticated');
      }
      try {
        const submitRaw = await circuit.request(Buffer.from(JSON.stringify({
          version: 1,
          mode: 'hidden-submit',
          token: descriptor.token,
          gateway_label: route.gatewayNodeLabel,
          request: msg,
        }), 'utf8'));
        const accepted = JSON.parse(submitRaw.toString('utf8')) as { accepted?: unknown; request_id?: unknown };
        if (accepted.accepted !== true || accepted.request_id !== msg.id) throw new Error('Hidden rendezvous rejected request');
        const waitRaw = await circuit.request(Buffer.from(JSON.stringify({
          version: 1,
          mode: 'hidden-wait',
          token: descriptor.token,
          request_id: msg.id,
        }), 'utf8'));
        const waited = JSON.parse(waitRaw.toString('utf8')) as { response?: unknown };
        const response = parseOverlayMessage(JSON.stringify(waited.response));
        if (!response || response.id !== msg.id || response.type !== 'response') {
          throw new Error('Hidden rendezvous response timed out or was invalid');
        }
        await this.writeEncryptedGatewayResponse(res, response, responseContext);
        return;
      } catch (error) {
        if (error instanceof Error && /SPKI pin mismatch/i.test(error.message)) this.tlsPinMismatches++;
        circuit.destroy('peer_failure');
        this.onionCircuitsDestroyed++;
        if (this.onionCircuit === circuit) this.onionCircuit = undefined;
        throw error;
      }
    }
    if (route.delivery?.mode !== 'public' || !route.gatewayEndpoints.length) {
      throw new Error('ONION_DELIVERY_REQUIRED: route has no supported delivery descriptor');
    }
    const circuit = await this.ensureOnionCircuit();
    const exitRequest = Buffer.from(JSON.stringify({
      version: 1,
      gateway_endpoint: route.gatewayEndpoints[0],
      gateway_node_label: route.gatewayNodeLabel,
      gateway_overlay_public_key: route.gatewayPubKeyB64,
      request: msg,
    }), 'utf8');
    try {
      const rawResponse = await circuit.request(exitRequest);
      const response = parseOverlayMessage(rawResponse.toString('utf8'));
      if (!response || response.id !== msg.id || response.type !== 'response') {
        throw new Error('Invalid onion exit response');
      }
      await this.writeEncryptedGatewayResponse(res, response, responseContext);
    } catch (error) {
      if (error instanceof Error && /SPKI pin mismatch/i.test(error.message)) this.tlsPinMismatches++;
      circuit.destroy('peer_failure');
      this.onionCircuitsDestroyed++;
      if (this.onionCircuit === circuit) this.onionCircuit = undefined;
      throw error;
    }
  }

  private async ensureOnionCircuit(terminalLabel?: string): Promise<OnionCircuitClient> {
    if (this.onionCircuit && !this.onionCircuit.state.shouldRebuild() &&
        (!terminalLabel || this.onionCircuit.path.terminal.label === terminalLabel)) return this.onionCircuit;
    if (this.onionCircuit && this.onionCircuit.state.snapshot().state !== 'destroyed') {
      this.onionCircuit.destroy('expired');
      this.onionCircuitsDestroyed++;
    }
    const directory = readRoutingCacheFile(this.cfg, { requireLocalSig: true });
    if (!directory) throw new Error('CIRCUIT_UNAVAILABLE: authenticated relay directory is missing');
    const candidates = relayCandidatesFromRoutingCache(directory);
    const guardStore = new GuardSetStore(
      undefined,
      this.onionLimits.guardLifetimeDays * 24 * 60 * 60_000,
    );
    const guardLabels = guardStore.loadOrSelect(candidates);
    const circuitPath = selectCircuitPath(candidates, {
      guardLabels,
      terminalLabel,
      allowSingleOperatorLoopbackTests: this.onionLimits.allowSingleOperatorLoopbackTests,
    });
    const circuit = new OnionCircuitClient(
      circuitPath,
      this.nodeLabel!,
      'entry',
      this.cfg,
      this.nodeCrypto,
      this.onionLimits,
    );
    await circuit.build();
    this.onionCircuitsBuilt++;
    this.onionCircuit = circuit;
    return circuit;
  }

  private async writeEncryptedGatewayResponse(
    res: http.ServerResponse,
    response: OverlayMessage,
    responseContext: EntryE2eResponseContext,
  ): Promise<void> {
    const envelope = parseHpkeEnvelope(response.payload.e2e);
    if (!envelope || envelope.direction !== 'response' ||
        envelope.request_id !== responseContext.requestId ||
        envelope.route_hash !== responseContext.routeHash) {
      throw new Error('Invalid encrypted Gateway response envelope');
    }
    let opened: unknown;
    try {
      opened = await openHpkeJson<unknown>(responseContext.privateKey, envelope);
    } catch (error) {
      this.hpkeFailures++;
      throw error;
    }
    const e2eResponse = parseE2eResponse(opened);
    if (e2eResponse.request_id !== responseContext.requestId ||
        e2eResponse.route_hash !== responseContext.routeHash ||
        !verifyGatewayResponse(e2eResponse, responseContext.gatewayIdentityPublicKey)) {
      throw new Error('Gateway response signature failed');
    }
    res.writeHead(e2eResponse.status, e2eResponse.headers);
    res.end(e2eResponse.body ? Buffer.from(e2eResponse.body, 'base64') : undefined);
  }

  private async relayPubkeyFor(target: UpstreamRelay): Promise<string | undefined> {
    if (!this.distributedMesh) return undefined;
    const pk = await this.resolver.resolveRelayPubkey(target.label);
    if (!pk) throw new Error(`Could not resolve relay pubkey for label "${target.label}"`);
    return pk;
  }

  private async forwardToRelayWithFailover(
    msg: OverlayMessage,
    res: http.ServerResponse,
    urlIndex: number,
    responseContext?: EntryE2eResponseContext,
  ): Promise<void> {
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
    } catch {
      this.relayFailures++;
      await this.forwardToRelayWithFailover(msg, res, urlIndex + 1, responseContext);
      return;
    }

    try {
      const response = await this.relayPool.request(url, signedMsg);
      const peer = await validateDistributedPeer({
        distributedMesh: this.distributedMesh,
        cfg: this.cfg,
        chain: this.chain,
        msg: response,
        expectedRole: 'relay',
        expectedLabel: target.label,
      });
      if (!peer.ok) {
        throw new Error(peer.error);
      }

      const ok = verifyIncomingOverlayFromPeer({
        distributedMesh: this.distributedMesh,
        mgr: this.sessionMgr,
        overlaySecret: loadCA().overlaySecret,
        expectedPeerPubKeyB64: peer.pubkey,
        msg: response,
      });
      if (!ok) {
        throw new Error('Unauthenticated overlay response');
      }

      if (response.id === msg.id && response.type === 'response') {
        if (responseContext) {
          const envelope = parseHpkeEnvelope(response.payload.e2e);
          if (!envelope || envelope.direction !== 'response' ||
              envelope.request_id !== responseContext.requestId ||
              envelope.route_hash !== responseContext.routeHash) {
            throw new Error('Invalid encrypted Gateway response envelope');
          }
          const opened = await openHpkeJson<unknown>(responseContext.privateKey, envelope);
          const e2eResponse = parseE2eResponse(opened);
          if (e2eResponse.request_id !== responseContext.requestId ||
              e2eResponse.route_hash !== responseContext.routeHash ||
              !verifyGatewayResponse(e2eResponse, responseContext.gatewayIdentityPublicKey)) {
            throw new Error('Gateway response signature failed');
          }
          res.writeHead(e2eResponse.status, e2eResponse.headers);
          res.end(e2eResponse.body ? Buffer.from(e2eResponse.body, 'base64') : undefined);
        } else {
          res.writeHead(response.payload.status ?? 502, response.payload.headers);
          if (response.payload.body) {
            res.end(Buffer.from(response.payload.body, 'base64'));
          } else {
            res.end();
          }
        }
        return;
      }
      throw new Error('Unexpected overlay response');
    } catch {
      this.relayFailures++;
      void this.forwardToRelayWithFailover(msg, res, urlIndex + 1, responseContext);
    }
  }

  private agentName(req: http.IncomingMessage): string {
    const value = singleHeader(req.headers['x-lattice-agent']) ?? process.env.LATTICE_AGENT ?? 'unknown';
    return normalizeAgentName(value);
  }

  private async verifyAgentRequest(
    req: http.IncomingMessage,
    agent: string,
    body: Buffer,
  ): Promise<{ ok: true; proof: NonNullable<OverlayMessage['payload']['agent_proof']> } | { ok: false; status: number; error: string }> {
    let publicKey: string | undefined;
    let certificate: unknown;
    try {
      const agentState = loadAgentPublicIdentity(agent);
      publicKey = agentState.publicKey;
      certificate = agentState.signedCert;
    } catch {
      certificate = portableAgentCertificate(req);
      const issuerId = signedCertificateIssuerId(certificate);
      const issuer = issuerId ? this.trustedAgentIssuers.get(issuerId) : undefined;
      const cert = issuer ? this.issuerCertificateCache.verify(certificate, issuer) : null;
      if (!cert) return { ok: false, status: 401, error: 'Unknown agent identity' };
      publicKey = cert.public_key;
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

    const payload = requestSignaturePayload({
      agent,
      method: req.method,
      host: singleHeader(req.headers.host),
      url: req.url,
      timestamp,
      bodyHash: hashRequestBody(body),
    });

    if (!publicKey || !verifySignature(payload, signature, publicKey)) {
      return { ok: false, status: 401, error: 'Invalid Lattice agent signature' };
    }
    // Entry replicas share this namespace, but Gateway's independent
    // end-to-end verification of the same request must not look like a replay.
    const compositeKey = entryReplayKey(agent, timestamp, nonce);
    let nonceAccepted: boolean;
    try {
      nonceAccepted = await this.replayStore.claim(compositeKey, getReplayWindowMs());
    } catch {
      return { ok: false, status: 503, error: 'REPLAY_STORE_UNAVAILABLE' };
    }
    if (!nonceAccepted) {
      return { ok: false, status: 401, error: 'REPLAY_DETECTED' };
    }

    return {
      ok: true,
      proof: {
        agent,
        public_key: publicKey,
        signature,
        timestamp,
        nonce,
        body_hash: hashRequestBody(body),
        host: singleHeader(req.headers.host) ?? '',
        certificate,
      },
    };
  }
}

function portableAgentCertificate(req: http.IncomingMessage): unknown | undefined {
  const header = singleHeader(req.headers['x-lattice-agent-certificate']);
  if (!header || Buffer.byteLength(header, 'utf8') > MAX_PORTABLE_AGENT_CERTIFICATE_HEADER_BYTES || !/^[A-Za-z0-9_-]+$/.test(header)) {
    return undefined;
  }
  try {
    const decoded = Buffer.from(header, 'base64url');
    if (decoded.length === 0 || decoded.length > MAX_PORTABLE_AGENT_CERTIFICATE_HEADER_BYTES) return undefined;
    return JSON.parse(decoded.toString('utf8'));
  } catch {
    return undefined;
  }
}

function signedCertificateIssuerId(signed: unknown): string | undefined {
  if (!signed || typeof signed !== 'object') return undefined;
  const issuer = (signed as { ca_cert_id?: unknown }).ca_cert_id;
  return typeof issuer === 'string' ? issuer : undefined;
}

function singleHeader(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

function overlayHeaders(headers: http.IncomingHttpHeaders): Record<string, string | string[] | number> {
  const result: Record<string, string | string[] | number> = {};
  let totalBytes = 0;
  for (const [name, value] of Object.entries(headers)) {
    if (value === undefined) continue;
    if (!/^[a-z0-9-]{1,128}$/i.test(name)) continue;
    if (Array.isArray(value)) {
      const filtered = value.filter(v => typeof v === 'string' && !/[\r\n]/.test(v)).slice(0, 16);
      const bytes = Buffer.byteLength(name, 'utf8') + filtered.reduce((sum, item) => sum + Buffer.byteLength(item, 'utf8'), 0);
      if (filtered.length && totalBytes + bytes <= MAX_OVERLAY_HEADER_BYTES) {
        result[name] = filtered;
        totalBytes += bytes;
      }
    } else if (!/[\r\n]/.test(value)) {
      const bytes = Buffer.byteLength(name, 'utf8') + Buffer.byteLength(value, 'utf8');
      if (totalBytes + bytes <= MAX_OVERLAY_HEADER_BYTES) {
        result[name] = value;
        totalBytes += bytes;
      }
    }
  }
  return result;
}

function entryReservationBytes(req: http.IncomingMessage): number {
  const contentLength = Number(singleHeader(req.headers['content-length']));
  if (!Number.isSafeInteger(contentLength) || contentLength < 0 || contentLength > MAX_AGENT_REQUEST_BYTES) {
    return Math.ceil(MAX_AGENT_REQUEST_BYTES * 4 / 3) + MAX_OVERLAY_HEADER_BYTES;
  }
  return Math.max(
    MIN_ENTRY_REQUEST_RESERVATION_BYTES,
    Math.ceil(contentLength * 4 / 3) + MAX_OVERLAY_HEADER_BYTES,
  );
}
