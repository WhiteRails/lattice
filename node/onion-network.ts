import * as crypto from 'crypto';
import { WebSocket, type ClientOptions, type RawData } from 'ws';
import { z } from 'zod';
import {
  ONION_CELL_BODY_BYTES,
  ONION_CELL_BYTES,
  ONION_AEAD_TAG_BYTES,
  ONION_INNER_BYTES,
  OnionCellCommand,
  OnionControlCommand,
  OnionStreamCommand,
  StrictSequence,
  addBackwardLayer,
  buildForwardOnionDepth,
  decodeOnionCell,
  decodeOnionControl,
  decodeStreamFragment,
  encodeOnionCell,
  encodeOnionControl,
  encodeStreamFragment,
  fragmentStream,
  peelBackwardOnionDepth,
  peelForwardLayer,
  type OnionCell,
} from './onion-cell';
import {
  answerNtorV3WithDerive,
  createNtorV3Client,
  finishNtorV3,
  ntorNodeId,
  type OnionHopKeys,
} from './onion-handshake';
import { OnionCircuitState } from './onion-circuit';
import type { CircuitPath, CircuitRelayCandidate } from './circuit-selector';
import type { LatticeNodeRole, LatticeNodeYaml, OnionCircuitConfig } from './node-config';
import { resolveNodeChainConfig, resolveOnionCircuitConfig } from './node-config';
import type { NodeCryptoBackend, NodeKeyDescriptor } from './node-crypto';
import { resolveRegisteredNode } from './peer-identity';
import { wsTlsClientOptions } from './ws-stack';
import {
  OnionCreate2Schema,
  OnionCreated2Schema,
  OnionExtend2Schema,
  OnionExtended2Schema,
  OnionWirePayloadType,
  createAuthenticatedOnionCreate2,
  decodeOnionWirePayload,
  encodeOnionWirePayload,
  verifyAuthenticatedOnionCreate2,
} from './onion-wire';

const MAX_EXIT_STREAM_BYTES = 1024 * 1024;
const LINK_TIMEOUT_MS = 30_000;

export interface OnionExitHandler {
  (payload: Buffer): Promise<Buffer>;
}

export interface OnionRegisteredPeer {
  active: boolean;
  roleBitmask: number;
  identityPubKeyB64: string;
}

export interface OnionRuntimeMetrics {
  active: number;
  built: number;
  destroyed: number;
  ntorFailures: number;
  replayFailures: number;
  invalidTags: number;
  paddingBytes: number;
}

interface RelayStreamState {
  nextFragment: number;
  requestChunks: Buffer[];
  requestBytes: number;
  responseFragments?: ReturnType<typeof fragmentStream>;
  nextResponseFragment: number;
}

interface RelayCircuitState {
  circuitId: number;
  hopIndex: number;
  keys: OnionHopKeys;
  forward: StrictSequence;
  backward: StrictSequence;
  downstreamForward: StrictSequence;
  downstreamBackward: StrictSequence;
  downstream?: OnionLink;
  downstreamCircuitId?: number;
  streams: Map<number, RelayStreamState>;
  processing: Promise<void>;
  destroyed: boolean;
}

export class OnionLink {
  private socket?: WebSocket;
  private connecting?: Promise<WebSocket>;
  private queue: Promise<unknown> = Promise.resolve();
  private closed = false;

  constructor(
    readonly url: string,
    private readonly options: ClientOptions,
    private readonly timeoutMs = LINK_TIMEOUT_MS,
  ) {}

  request(cell: OnionCell): Promise<OnionCell> {
    const operation = this.queue.then(() => this.requestNow(cell));
    this.queue = operation.catch(() => undefined);
    return operation;
  }

  close(): void {
    this.closed = true;
    this.socket?.close();
    this.socket = undefined;
  }

  private async requestNow(cell: OnionCell): Promise<OnionCell> {
    if (this.closed) throw new Error('Onion link is closed');
    const socket = await this.ensureConnected();
    return new Promise<OnionCell>((resolve, reject) => {
      let settled = false;
      const finish = (error?: Error, response?: OnionCell) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        socket.off('message', onMessage);
        socket.off('close', onClose);
        if (error) reject(error); else resolve(response!);
      };
      const timer = setTimeout(() => finish(new Error('Onion link response timed out')), this.timeoutMs);
      const onClose = () => finish(new Error('Onion link closed'));
      const onMessage = (raw: RawData, isBinary: boolean) => {
        try {
          if (!isBinary) throw new Error('Onion links accept binary cells only');
          finish(undefined, decodeOnionCell(rawDataBuffer(raw)));
        } catch (error) {
          finish(error instanceof Error ? error : new Error(String(error)));
        }
      };
      socket.once('message', onMessage);
      socket.once('close', onClose);
      socket.send(encodeOnionCell(cell), { binary: true }, error => {
        if (error) finish(error);
      });
    });
  }

  private ensureConnected(): Promise<WebSocket> {
    if (this.socket?.readyState === WebSocket.OPEN) return Promise.resolve(this.socket);
    if (this.connecting) return this.connecting;
    const socket = new WebSocket(this.url, undefined, {
      rejectUnauthorized: true,
      ...this.options,
      maxPayload: ONION_CELL_BYTES,
    });
    this.socket = socket;
    this.connecting = new Promise<WebSocket>((resolve, reject) => {
      const timer = setTimeout(() => {
        socket.terminate();
        reject(new Error('Onion link connection timed out'));
      }, this.timeoutMs);
      socket.once('open', () => { clearTimeout(timer); resolve(socket); });
      socket.once('error', error => { clearTimeout(timer); reject(error); });
    }).finally(() => { this.connecting = undefined; });
    socket.once('close', () => { if (this.socket === socket) this.socket = undefined; });
    socket.on('error', () => {});
    return this.connecting;
  }
}

export class OnionCircuitClient {
  readonly state: OnionCircuitState;
  private guardLink?: OnionLink;

  constructor(
    readonly path: CircuitPath,
    private readonly clientLabel: string,
    private readonly clientRole: LatticeNodeRole,
    private readonly cfg: LatticeNodeYaml | null,
    private readonly cryptoBackend: NodeCryptoBackend,
    limits: OnionCircuitConfig = resolveOnionCircuitConfig(cfg),
  ) {
    for (const relay of [path.guard, path.middle, path.terminal]) {
      assertSafeNextEndpoint(relay.endpoint, limits.allowInsecureLoopbackTests);
      if (new URL(relay.endpoint).protocol === 'wss:' && !/^[a-f0-9]{64}$/.test(relay.tlsSpkiSha256 ?? '')) {
        throw new Error(`ONION_TLS_PIN_REQUIRED: ${relay.label}`);
      }
    }
    this.state = new OnionCircuitState(path, limits);
  }

  async build(): Promise<void> {
    if (this.guardLink) throw new Error('Onion circuit build already started');
    this.guardLink = candidateLink(this.path.guard, this.cfg);
    try {
      await this.createFirstHop(this.path.guard);
      await this.extend(this.path.middle, 1);
      await this.extend(this.path.terminal, 2);
    } catch (error) {
      this.destroy('protocol_error');
      throw error;
    }
  }

  async request(payload: Buffer): Promise<Buffer> {
    if (!this.guardLink) throw new Error('Onion circuit is not built');
    const streamId = this.state.openStream();
    try {
      const requestFragments = fragmentStream(streamId, payload, OnionStreamCommand.Data);
      let responseFragment: ReturnType<typeof decodeStreamFragment> | undefined;
      for (const fragment of requestFragments) {
        responseFragment = await this.exchangeInner(encodeStreamFragment(fragment));
        if (!fragment.final && responseFragment.command !== OnionStreamCommand.Sendme) {
          throw new Error('Expected onion SENDME while fragmenting request');
        }
      }
      if (!responseFragment || responseFragment.command !== OnionStreamCommand.Data || responseFragment.fragmentIndex !== 0) {
        throw new Error('Invalid first onion response fragment');
      }
      const chunks = [responseFragment.data];
      let expected = 1;
      while (!responseFragment.final) {
        responseFragment = await this.exchangeInner(encodeStreamFragment({
          command: OnionStreamCommand.Sendme,
          streamId,
          fragmentIndex: expected,
          final: true,
          data: Buffer.alloc(0),
        }));
        if (responseFragment.command !== OnionStreamCommand.Data || responseFragment.fragmentIndex !== expected) {
          throw new Error('Out-of-order onion response fragment');
        }
        chunks.push(responseFragment.data);
        expected++;
      }
      return Buffer.concat(chunks);
    } catch (error) {
      this.destroy('protocol_error');
      throw error;
    } finally {
      if (this.state.snapshot().state !== 'destroyed') this.state.closeStream(streamId);
    }
  }

  destroy(reason: Parameters<OnionCircuitState['destroy']>[0] = 'closed'): void {
    this.state.destroy(reason);
    this.guardLink?.close();
    this.guardLink = undefined;
  }

  private async createFirstHop(candidate: CircuitRelayCandidate): Promise<void> {
    const client = createNtorV3Client(ntorNodeId(candidate.identityPubKeyB64), candidate.onionPubKeyB64Url);
    const identity = await this.cryptoBackend.currentKey('identity');
    const authenticatedCreate = await createAuthenticatedOnionCreate2(
      this.state.linkCircuitIds[0], 0, this.clientLabel, this.clientRole, client.create, identity, this.cryptoBackend,
    );
    const response = await this.guardLink!.request({
      command: OnionCellCommand.Create2, flags: 0, circuitId: this.state.linkCircuitIds[0], sequence: 0n,
      body: encodeOnionWirePayload(OnionWirePayloadType.Create2, authenticatedCreate),
    });
    if (response.command !== OnionCellCommand.Created2 || response.circuitId !== this.state.linkCircuitIds[0] || response.sequence !== 0n) {
      throw new Error('Invalid CREATED2 response from guard');
    }
    const wire = decodeOnionWirePayload(response.body);
    const created = OnionCreated2Schema.parse(wire.value);
    if (wire.type !== OnionWirePayloadType.Created2 || created.server_label !== candidate.label) {
      throw new Error('Guard CREATED2 identity mismatch');
    }
    this.state.addHop(finishNtorV3(client, created.created));
  }

  private async extend(candidate: CircuitRelayCandidate, hopIndex: 1 | 2): Promise<void> {
    const client = createNtorV3Client(ntorNodeId(candidate.identityPubKeyB64), candidate.onionPubKeyB64Url);
    const depth = hopIndex;
    const forwardContexts = this.state.forwardContexts(depth);
    const plaintextBytes = ONION_CELL_BODY_BYTES - depth * ONION_AEAD_TAG_BYTES;
    const control = encodeOnionControl(OnionControlCommand.Extend2, {
      version: 1,
      next_label: candidate.label,
      next_endpoint: candidate.endpoint,
      next_circuit_id: this.state.linkCircuitIds[hopIndex],
      hop_index: hopIndex,
      create: client.create,
      tls_spki_sha256: candidate.tlsSpkiSha256,
    }, plaintextBytes);
    const response = await this.guardLink!.request({
      command: OnionCellCommand.Relay,
      flags: 0,
      circuitId: this.state.linkCircuitIds[0],
      sequence: forwardContexts[0]!.sequence,
      body: buildForwardOnionDepth(control, this.state.keys(depth), forwardContexts),
    });
    if (response.command !== OnionCellCommand.Relay || response.circuitId !== this.state.linkCircuitIds[0]) {
      throw new Error('Invalid EXTENDED2 response');
    }
    const backwardContexts = this.state.backwardContexts(depth);
    if (response.sequence !== backwardContexts[0]!.sequence) throw new Error('Out-of-order EXTENDED2 response');
    const opened = peelBackwardOnionDepth(response.body, this.state.keys(depth), backwardContexts);
    const decoded = decodeOnionControl(opened);
    if (!decoded || decoded.command !== OnionControlCommand.Extended2) throw new Error('Missing EXTENDED2 control');
    const extended = OnionExtended2Schema.parse(decoded.value);
    if (extended.next_label !== candidate.label) throw new Error('EXTENDED2 relay mismatch');
    this.state.addHop(finishNtorV3(client, extended.created));
  }

  private async exchangeInner(inner: Buffer) {
    const contexts = this.state.forwardContexts();
    const response = await this.guardLink!.request({
      command: OnionCellCommand.Relay, flags: 0,
      circuitId: this.state.linkCircuitIds[0], sequence: contexts[0]!.sequence,
      body: buildForwardOnionDepth(inner, this.state.keys(), contexts),
    });
    if (response.command !== OnionCellCommand.Relay || response.circuitId !== this.state.linkCircuitIds[0]) {
      throw new Error('Invalid onion relay response');
    }
    const backward = this.state.backwardContexts();
    if (response.sequence !== backward[0]!.sequence) throw new Error('Out-of-order onion relay response');
    return decodeStreamFragment(peelBackwardOnionDepth(response.body, this.state.keys(), backward));
  }
}

/** Handles binary onion cells attached to an existing Relay WebSocket listener. */
export class OnionRelayRuntime {
  private readonly circuits = new WeakMap<WebSocket, Map<number, RelayCircuitState>>();
  private readonly limits: OnionCircuitConfig;
  private readonly linkProofNonces = new Map<string, number>();
  private readonly chain;
  private readonly metrics: OnionRuntimeMetrics = {
    active: 0, built: 0, destroyed: 0, ntorFailures: 0,
    replayFailures: 0, invalidTags: 0, paddingBytes: 0,
  };

  constructor(
    private readonly nodeLabel: string,
    private readonly cfg: LatticeNodeYaml | null,
    private readonly cryptoBackend: NodeCryptoBackend,
    private readonly exitHandler: OnionExitHandler,
    private readonly resolvePeer?: (label: string) => Promise<OnionRegisteredPeer | null>,
  ) {
    this.limits = resolveOnionCircuitConfig(cfg);
    this.chain = resolveNodeChainConfig(cfg);
  }

  handles(raw: RawData, isBinary: boolean): boolean {
    return isBinary || rawDataBuffer(raw).length === ONION_CELL_BYTES;
  }

  snapshot(): Readonly<OnionRuntimeMetrics> {
    return { ...this.metrics };
  }

  handle(ws: WebSocket, raw: RawData, isBinary: boolean): void {
    if (!isBinary) {
      ws.close(1003, 'onion-v1 requires binary cells');
      return;
    }
    let cell: OnionCell;
    try { cell = decodeOnionCell(rawDataBuffer(raw)); } catch {
      ws.close(1002, 'invalid onion cell');
      return;
    }
    const map = this.circuitMap(ws);
    if (cell.command === OnionCellCommand.Create2) {
      void this.createCircuit(ws, map, cell).catch(() => {
        this.metrics.ntorFailures++;
        this.destroyCircuit(ws, map, cell.circuitId);
      });
      return;
    }
    const state = map.get(cell.circuitId);
    if (!state || state.destroyed) {
      this.sendDestroy(ws, cell.circuitId);
      return;
    }
    state.processing = state.processing.then(() => this.processCell(ws, map, state, cell))
      .catch(() => {
        this.metrics.invalidTags++;
        this.destroyCircuit(ws, map, state.circuitId);
      });
  }

  closeSocket(ws: WebSocket): void {
    const map = this.circuits.get(ws);
    if (!map) return;
    for (const state of map.values()) this.destroyState(state);
    map.clear();
  }

  private async createCircuit(ws: WebSocket, map: Map<number, RelayCircuitState>, cell: OnionCell): Promise<void> {
    if (cell.sequence !== 0n || map.has(cell.circuitId)) throw new Error('Invalid CREATE2 sequence or duplicate circuit');
    const decoded = decodeOnionWirePayload(cell.body);
    if (decoded.type !== OnionWirePayloadType.Create2) throw new Error('Expected CREATE2 payload');
    const unverified = OnionCreate2Schema.parse(decoded.value);
    const registeredClient = this.resolvePeer
      ? await this.resolvePeer(unverified.client_label)
      : await resolveRegisteredNode(this.cfg, this.chain, unverified.client_label);
    const expectedRoleBit = unverified.client_role === 'entry' ? 1 : unverified.client_role === 'relay' ? 2 : 4;
    if (!registeredClient?.active || (registeredClient.roleBitmask & expectedRoleBit) === 0 || !registeredClient.identityPubKeyB64) {
      throw new Error('Unregistered CREATE2 link peer');
    }
    const request = verifyAuthenticatedOnionCreate2(
      unverified,
      cell.circuitId,
      unverified.client_label,
      unverified.client_role,
      identityDescriptor(registeredClient.identityPubKeyB64),
    );
    this.claimLinkProofNonce(request.client_label, request.nonce);
    const [identity, onion] = await this.cryptoBackend.ensureKeys(['identity', 'onion']);
    if (request.create.node_id !== ntorNodeId(identity.publicKey)) throw new Error('CREATE2 node identity mismatch');
    const answered = await answerNtorV3WithDerive(
      request.create,
      ntorNodeId(identity.publicKey),
      onion.publicKey,
      peerPublic => this.cryptoBackend.deriveX25519(onion.keyId, peerPublic),
    );
    const state: RelayCircuitState = {
      circuitId: cell.circuitId,
      hopIndex: request.hop_index,
      keys: answered.keys,
      forward: new StrictSequence(), backward: new StrictSequence(),
      downstreamForward: new StrictSequence(), downstreamBackward: new StrictSequence(),
      streams: new Map(), processing: Promise.resolve(), destroyed: false,
    };
    map.set(cell.circuitId, state);
    this.metrics.active++;
    this.metrics.built++;
    this.send(ws, {
      command: OnionCellCommand.Created2, flags: 0, circuitId: cell.circuitId, sequence: 0n,
      body: encodeOnionWirePayload(OnionWirePayloadType.Created2, {
        version: 1, server_label: this.nodeLabel, created: answered.created,
      }),
    });
  }

  private async processCell(
    ws: WebSocket,
    map: Map<number, RelayCircuitState>,
    state: RelayCircuitState,
    cell: OnionCell,
  ): Promise<void> {
    if (cell.command === OnionCellCommand.Destroy) {
      this.destroyCircuit(ws, map, state.circuitId);
      return;
    }
    if (cell.command !== OnionCellCommand.Relay) throw new Error('Unexpected onion command');
    state.forward.claim(cell.sequence);
    const peeled = peelForwardLayer(cell.body, state.hopIndex, state.keys, {
      circuitId: state.circuitId, sequence: cell.sequence,
    });
    const control = decodeOnionControl(peeled.meaningful);
    if (control) {
      if (control.command !== OnionControlCommand.Extend2) throw new Error('Unexpected forward onion control');
      await this.extend(ws, state, OnionExtend2Schema.parse(control.value));
      return;
    }
    if (state.downstream && state.downstreamCircuitId) {
      const downSequence = state.downstreamForward.issue();
      const response = await state.downstream.request({
        command: OnionCellCommand.Relay, flags: 0, circuitId: state.downstreamCircuitId,
        sequence: downSequence, body: peeled.wireBody,
      });
      if (response.command !== OnionCellCommand.Relay || response.circuitId !== state.downstreamCircuitId) {
        throw new Error('Invalid downstream onion response');
      }
      state.downstreamBackward.claim(response.sequence);
      this.sendBackward(ws, state, response.body);
      return;
    }
    if (state.hopIndex !== 2 || peeled.meaningful.length !== ONION_INNER_BYTES) throw new Error('Incomplete onion path');
    const responseInner = await this.handleExitFragment(state, decodeStreamFragment(peeled.meaningful));
    const wire = crypto.randomBytes(ONION_CELL_BODY_BYTES);
    responseInner.copy(wire, 0);
    this.sendBackward(ws, state, wire);
  }

  private async extend(ws: WebSocket, state: RelayCircuitState, extend: z.infer<typeof OnionExtend2Schema>): Promise<void> {
    if (state.downstream || extend.hop_index !== state.hopIndex + 1) throw new Error('Invalid circuit extension depth');
    assertSafeNextEndpoint(extend.next_endpoint, this.limits.allowInsecureLoopbackTests);
    const link = new OnionLink(extend.next_endpoint, wsTlsClientOptions(this.cfg, extend.tls_spki_sha256));
    try {
      const createdCell = await link.request({
        command: OnionCellCommand.Create2, flags: 0, circuitId: extend.next_circuit_id, sequence: 0n,
        body: encodeOnionWirePayload(
          OnionWirePayloadType.Create2,
          await createAuthenticatedOnionCreate2(
            extend.next_circuit_id,
            extend.hop_index,
            this.nodeLabel,
            'relay',
            extend.create,
            await this.cryptoBackend.currentKey('identity'),
            this.cryptoBackend,
          ),
        ),
      });
      if (createdCell.command !== OnionCellCommand.Created2 || createdCell.circuitId !== extend.next_circuit_id) {
        throw new Error('Invalid downstream CREATED2');
      }
      const decoded = decodeOnionWirePayload(createdCell.body);
      const created = OnionCreated2Schema.parse(decoded.value);
      if (decoded.type !== OnionWirePayloadType.Created2 || created.server_label !== extend.next_label) {
        throw new Error('Downstream relay identity mismatch');
      }
      state.downstream = link;
      state.downstreamCircuitId = extend.next_circuit_id;
      const plaintextBytes = ONION_CELL_BODY_BYTES - (state.hopIndex + 1) * ONION_AEAD_TAG_BYTES;
      const plaintext = encodeOnionControl(OnionControlCommand.Extended2, {
        version: 1, next_label: extend.next_label, created: created.created,
      }, plaintextBytes);
      const wire = crypto.randomBytes(ONION_CELL_BODY_BYTES);
      plaintext.copy(wire, 0);
      this.sendBackward(ws, state, wire);
    } catch (error) {
      link.close();
      throw error;
    }
  }

  private async handleExitFragment(state: RelayCircuitState, fragment: ReturnType<typeof decodeStreamFragment>): Promise<Buffer> {
    let stream = state.streams.get(fragment.streamId);
    if (!stream) {
      if (state.streams.size >= this.limits.maxConcurrentStreams) throw new Error('Exit stream backpressure');
      stream = { nextFragment: 0, requestChunks: [], requestBytes: 0, nextResponseFragment: 0 };
      state.streams.set(fragment.streamId, stream);
    }
    if (fragment.command === OnionStreamCommand.Sendme) {
      const next = stream.responseFragments?.[stream.nextResponseFragment++];
      if (!next || next.fragmentIndex !== fragment.fragmentIndex) throw new Error('Invalid response SENDME');
      if (next.final) state.streams.delete(fragment.streamId);
      return encodeStreamFragment(next);
    }
    if (fragment.command !== OnionStreamCommand.Data || stream.responseFragments || fragment.fragmentIndex !== stream.nextFragment++) {
      throw new Error('Invalid request stream fragment');
    }
    stream.requestBytes += fragment.data.length;
    this.metrics.paddingBytes += Math.max(0, ONION_INNER_BYTES - 12 - fragment.data.length);
    if (stream.requestBytes > MAX_EXIT_STREAM_BYTES) throw new Error('Exit request stream too large');
    stream.requestChunks.push(fragment.data);
    if (!fragment.final) {
      return encodeStreamFragment({
        command: OnionStreamCommand.Sendme, streamId: fragment.streamId,
        fragmentIndex: fragment.fragmentIndex, final: true, data: Buffer.alloc(0),
      });
    }
    const response = await this.exitHandler(Buffer.concat(stream.requestChunks));
    if (response.length > MAX_EXIT_STREAM_BYTES) throw new Error('Exit response stream too large');
    stream.responseFragments = fragmentStream(fragment.streamId, response, OnionStreamCommand.Data);
    const first = stream.responseFragments[0]!;
    stream.nextResponseFragment = 1;
    if (first.final) state.streams.delete(fragment.streamId);
    return encodeStreamFragment(first);
  }

  private sendBackward(ws: WebSocket, state: RelayCircuitState, wireBody: Buffer): void {
    const sequence = state.backward.issue();
    const body = addBackwardLayer(wireBody, state.hopIndex, state.keys, {
      circuitId: state.circuitId, sequence,
    });
    this.send(ws, { command: OnionCellCommand.Relay, flags: 0, circuitId: state.circuitId, sequence, body });
  }

  private circuitMap(ws: WebSocket): Map<number, RelayCircuitState> {
    let map = this.circuits.get(ws);
    if (!map) {
      map = new Map();
      this.circuits.set(ws, map);
      ws.once('close', () => this.closeSocket(ws));
    }
    return map;
  }

  private destroyCircuit(ws: WebSocket, map: Map<number, RelayCircuitState>, circuitId: number): void {
    const state = map.get(circuitId);
    if (state) this.destroyState(state);
    map.delete(circuitId);
    this.sendDestroy(ws, circuitId);
  }

  private destroyState(state: RelayCircuitState): void {
    if (state.destroyed) return;
    state.destroyed = true;
    this.metrics.active = Math.max(0, this.metrics.active - 1);
    this.metrics.destroyed++;
    state.downstream?.close();
    state.streams.clear();
    state.keys.forwardKey.fill(0);
    state.keys.backwardKey.fill(0);
    state.keys.forwardNonceSalt.fill(0);
    state.keys.backwardNonceSalt.fill(0);
  }

  private sendDestroy(ws: WebSocket, circuitId: number): void {
    if (ws.readyState !== WebSocket.OPEN || circuitId < 1) return;
    this.send(ws, {
      command: OnionCellCommand.Destroy, flags: 0, circuitId, sequence: 0n,
      body: crypto.randomBytes(ONION_CELL_BODY_BYTES),
    });
  }

  private send(ws: WebSocket, cell: OnionCell): void {
    if (ws.readyState === WebSocket.OPEN) ws.send(encodeOnionCell(cell), { binary: true });
  }

  private claimLinkProofNonce(label: string, nonce: string, now = Date.now()): void {
    for (const [key, expires] of this.linkProofNonces) {
      if (expires <= now) this.linkProofNonces.delete(key);
    }
    const key = `${label}\0${nonce}`;
    if (this.linkProofNonces.has(key)) {
      this.metrics.replayFailures++;
      throw new Error('Replayed CREATE2 link proof');
    }
    if (this.linkProofNonces.size >= 100_000) throw new Error('CREATE2 replay cache capacity reached');
    this.linkProofNonces.set(key, now + 30_000);
  }
}

function candidateLink(candidate: CircuitRelayCandidate, cfg: LatticeNodeYaml | null): OnionLink {
  return new OnionLink(candidate.endpoint, wsTlsClientOptions(cfg, candidate.tlsSpkiSha256));
}

function assertSafeNextEndpoint(value: string, allowInsecureLoopback: boolean): void {
  const url = new URL(value);
  if (url.protocol === 'wss:') return;
  const host = url.hostname.replace(/^\[|]$/g, '').toLowerCase();
  if (url.protocol === 'ws:' && allowInsecureLoopback && ['127.0.0.1', '::1', 'localhost'].includes(host)) return;
  throw new Error('ONION_WSS_REQUIRED: circuit extension endpoint must use WSS');
}

function rawDataBuffer(raw: RawData): Buffer {
  if (Buffer.isBuffer(raw)) return raw;
  if (Array.isArray(raw)) return Buffer.concat(raw);
  if (raw instanceof ArrayBuffer) return Buffer.from(raw);
  throw new Error('Unsupported WebSocket binary payload');
}

function identityDescriptor(publicKey: string): NodeKeyDescriptor {
  const keyDer = Buffer.from(publicKey, 'base64');
  return {
    version: 1,
    keyId: crypto.createHash('sha256').update(keyDer).digest('hex'),
    purpose: 'identity',
    algorithm: 'ed25519',
    publicKey,
    createdAt: new Date(0).toISOString(),
    status: 'active',
  };
}
