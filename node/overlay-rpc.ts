/**
 * Bounded, multiplexed request/response transport for overlay hops.
 *
 * The wire format remains the signed OverlayMessage JSON frame for backwards
 * compatibility. The transport deliberately has no authority of its own:
 * callers still validate the responding peer and its overlay authentication.
 * It only correlates response IDs and reuses a verified TLS connection.
 */
import { WebSocket, type ClientOptions } from 'ws';
import { MAX_OVERLAY_FRAME_BYTES, parseOverlayMessage, type OverlayMessage } from './message';

export interface OverlayRpcClientOptions {
  /** Bounds in-flight work and supplies backpressure before memory is exhausted. */
  maxPending?: number;
  /** Applies to connection establishment and each request. */
  requestTimeoutMs?: number;
  wsOptions?: ClientOptions;
}

export interface OverlayRpcPoolOptions extends OverlayRpcClientOptions {
  /** Bound resident endpoint connections so route churn cannot retain sockets forever. */
  maxClients?: number;
  /** Bound work across all endpoint connections, not merely per socket. */
  maxTotalPending?: number;
}

interface PendingRequest {
  resolve: (message: OverlayMessage) => void;
  reject: (error: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

const DEFAULT_MAX_PENDING = 4_096;
const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_POOL_CLIENTS = 1_024;
const DEFAULT_MAX_POOL_PENDING = 8_192;

/** Cell-level tuning for outbound overlay resources. Invalid settings fail fast. */
export function overlayRpcPoolOptionsFromEnv(env: NodeJS.ProcessEnv = process.env): OverlayRpcPoolOptions {
  const maxClients = configuredPoolLimit(
    env.LATTICE_OVERLAY_RPC_MAX_CLIENTS, DEFAULT_MAX_POOL_CLIENTS, 32, 8_192,
    'LATTICE_OVERLAY_RPC_MAX_CLIENTS',
  );
  const maxPending = configuredPoolLimit(
    env.LATTICE_OVERLAY_RPC_MAX_PENDING_PER_CONNECTION, DEFAULT_MAX_PENDING, 1, 8_192,
    'LATTICE_OVERLAY_RPC_MAX_PENDING_PER_CONNECTION',
  );
  const maxTotalPending = configuredPoolLimit(
    env.LATTICE_OVERLAY_RPC_MAX_PENDING, DEFAULT_MAX_POOL_PENDING, 32, 65_536,
    'LATTICE_OVERLAY_RPC_MAX_PENDING',
  );
  if (maxPending > maxTotalPending) {
    throw new Error('LATTICE_OVERLAY_RPC_MAX_PENDING_PER_CONNECTION cannot exceed LATTICE_OVERLAY_RPC_MAX_PENDING');
  }
  return { maxClients, maxPending, maxTotalPending };
}

/**
 * One persistent overlay connection. Concurrent requests are multiplexed by
 * OverlayMessage.id. A connection failure rejects only the outstanding work;
 * the next request transparently establishes a fresh connection.
 */
export class OverlayRpcClient {
  private socket: WebSocket | undefined;
  private connecting: Promise<WebSocket> | undefined;
  private readonly pending = new Map<string, PendingRequest>();
  private closed = false;
  private readonly maxPending: number;
  private readonly requestTimeoutMs: number;

  constructor(
    readonly url: string,
    private readonly options: OverlayRpcClientOptions = {},
  ) {
    this.maxPending = options.maxPending ?? DEFAULT_MAX_PENDING;
    this.requestTimeoutMs = options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
  }

  get inFlight(): number {
    return this.pending.size;
  }

  async request(message: OverlayMessage): Promise<OverlayMessage> {
    if (this.closed) throw new Error(`Overlay client is closed: ${this.url}`);
    if (this.pending.has(message.id)) throw new Error(`Duplicate overlay request id: ${message.id}`);
    if (this.pending.size >= this.maxPending) {
      throw new Error(`Overlay connection backpressure: ${this.url} has ${this.maxPending} in-flight requests`);
    }

    return new Promise<OverlayMessage>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.rejectPending(message.id, new Error(`Overlay request timed out: ${this.url}`));
      }, this.requestTimeoutMs);
      this.pending.set(message.id, { resolve, reject, timer });

      void this.ensureConnected().then((socket) => {
        // The request could have timed out while the TCP/TLS connection opened.
        if (!this.pending.has(message.id)) return;
        if (socket.readyState !== WebSocket.OPEN) {
          this.rejectPending(message.id, new Error(`Overlay connection is not open: ${this.url}`));
          return;
        }
        try {
          socket.send(JSON.stringify(message), (error) => {
            if (error) this.rejectPending(message.id, new Error(`Overlay send failed: ${error.message}`));
          });
        } catch (error) {
          this.rejectPending(message.id, error instanceof Error ? error : new Error(String(error)));
        }
      }).catch((error: unknown) => {
        this.rejectPending(message.id, error instanceof Error ? error : new Error(String(error)));
      });
    });
  }

  close(): void {
    this.closed = true;
    const error = new Error(`Overlay client closed: ${this.url}`);
    for (const id of [...this.pending.keys()]) this.rejectPending(id, error);
    this.socket?.close();
    this.socket = undefined;
  }

  private ensureConnected(): Promise<WebSocket> {
    if (this.socket?.readyState === WebSocket.OPEN) return Promise.resolve(this.socket);
    if (this.connecting) return this.connecting;

    const socket = new WebSocket(this.url, undefined, {
      rejectUnauthorized: true,
      ...this.options.wsOptions,
      // This is a protocol invariant, not a caller tuning option. A remote
      // endpoint must never make the outbound pool retain a larger frame than
      // Relay/Gateway ingress accepts.
      maxPayload: MAX_OVERLAY_FRAME_BYTES,
    });
    this.socket = socket;
    this.connecting = new Promise<WebSocket>((resolve, reject) => {
      let settled = false;
      const failConnect = (error: Error) => {
        if (settled) return;
        settled = true;
        reject(error);
      };
      socket.once('open', () => {
        if (settled) return;
        settled = true;
        resolve(socket);
      });
      socket.once('error', (error) => failConnect(error));
      socket.once('close', () => failConnect(new Error(`Overlay connection closed during setup: ${this.url}`)));
    }).finally(() => {
      this.connecting = undefined;
    });

    socket.on('message', (raw) => {
      const response = parseOverlayMessage(raw.toString());
      if (!response) return;
      const pending = this.pending.get(response.id);
      if (!pending) return;
      clearTimeout(pending.timer);
      this.pending.delete(response.id);
      pending.resolve(response);
    });
    socket.on('error', () => {
      // The close handler below fans the failure out to pending streams. Keeping
      // an error listener also prevents an unhandled EventEmitter error.
    });
    socket.on('close', () => {
      // A late close from an obsolete socket must never tear down streams that
      // were already moved to a replacement connection.
      if (this.socket !== socket) return;
      this.socket = undefined;
      const error = new Error(`Overlay connection closed: ${this.url}`);
      for (const id of [...this.pending.keys()]) this.rejectPending(id, error);
    });
    return this.connecting;
  }

  private rejectPending(id: string, error: Error): void {
    const pending = this.pending.get(id);
    if (!pending) return;
    clearTimeout(pending.timer);
    this.pending.delete(id);
    pending.reject(error);
  }
}

/** Reuses one bounded multiplexed connection for each resolved endpoint. */
export class OverlayRpcPool {
  private readonly clients = new Map<string, OverlayRpcClient>();
  private readonly maxClients: number;
  private readonly maxTotalPending: number;
  private totalPending = 0;

  constructor(private readonly options: OverlayRpcPoolOptions = {}) {
    this.maxClients = validPoolLimit(options.maxClients ?? DEFAULT_MAX_POOL_CLIENTS, 'maxClients');
    this.maxTotalPending = validPoolLimit(options.maxTotalPending ?? DEFAULT_MAX_POOL_PENDING, 'maxTotalPending');
  }

  get clientCount(): number { return this.clients.size; }

  async request(url: string, message: OverlayMessage): Promise<OverlayMessage> {
    if (this.totalPending >= this.maxTotalPending) {
      throw new Error(`Overlay pool backpressure: ${this.maxTotalPending} total in-flight requests`);
    }
    let client = this.clients.get(url);
    if (!client) {
      this.evictIdleClientIfNeeded();
      if (this.clients.size >= this.maxClients) {
        throw new Error(`Overlay pool endpoint capacity: ${this.maxClients} resident connections`);
      }
      client = new OverlayRpcClient(url, this.options);
      this.clients.set(url, client);
    } else {
      // Map insertion order is our LRU order. Refresh on every use.
      this.clients.delete(url);
      this.clients.set(url, client);
    }
    this.totalPending++;
    try {
      return await client.request(message);
    } finally {
      // Client rejections, timeouts and pool.close() all flow through here so
      // capacity cannot leak after an endpoint failure.
      this.totalPending = Math.max(0, this.totalPending - 1);
    }
  }

  close(): void {
    for (const client of this.clients.values()) client.close();
    this.clients.clear();
  }

  inFlight(url?: string): number {
    if (url) return this.clients.get(url)?.inFlight ?? 0;
    return this.totalPending;
  }

  private evictIdleClientIfNeeded(): void {
    if (this.clients.size < this.maxClients) return;
    for (const [url, client] of this.clients) {
      if (client.inFlight !== 0) continue;
      client.close();
      this.clients.delete(url);
      return;
    }
  }
}

function validPoolLimit(value: number, name: string): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > 65_536) {
    throw new Error(`${name} must be an integer between 1 and 65536`);
  }
  return value;
}

function configuredPoolLimit(raw: string | undefined, fallback: number, minimum: number, maximum: number, name: string): number {
  if (raw === undefined || raw.trim() === '') return fallback;
  if (!/^[0-9]+$/.test(raw.trim())) throw new Error(`${name} must be an integer`);
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} must be between ${minimum} and ${maximum}`);
  }
  return value;
}
