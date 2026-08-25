import * as crypto from 'crypto';
import * as net from 'net';
import * as tls from 'tls';
import { NonceStore } from './nonce-store';

// Lattice only sends SET NX PX and expects a small simple/bulk response. Keep
// an incomplete RESP stream from becoming an unbounded retained Buffer.
const MAX_REDIS_RESPONSE_BUFFER_BYTES = 64 * 1024;

/** Atomically records an idempotency/replay key for its validity window. */
export interface ReplayStore {
  claim(key: string, ttlMs: number): Promise<boolean>;
}

/** Default for one-process development only. Production replicas use Redis. */
export class LocalReplayStore implements ReplayStore {
  constructor(private readonly nonces = new NonceStore()) {}

  async claim(key: string, ttlMs: number): Promise<boolean> {
    return this.nonces.add(key, ttlMs);
  }
}

export interface RedisReplayStoreOptions {
  prefix?: string;
  poolSize?: number;
  maxPendingPerConnection?: number;
  commandTimeoutMs?: number;
  /** Bound Redis Cluster redirect targets; never turn MOVED replies into unlimited pools. */
  maxClusterEndpoints?: number;
}

/**
 * Small RESP client for the one Redis primitive Lattice needs: SET NX PX.
 * It keeps a bounded pool of persistent connections and never logs credentials
 * or replay keys. `rediss://` enables TLS with normal Node certificate checks.
 */
export class RedisReplayStore implements ReplayStore {
  private readonly clients: RedisConnection[];
  private readonly clusterSlots = new Map<number, string>();
  private readonly clusterClients = new Map<string, RedisConnection[]>();
  private next = 0;
  private readonly prefix: string;
  private readonly target: RedisTarget;
  private readonly poolSize: number;
  private readonly maxPendingPerConnection: number;
  private readonly commandTimeoutMs: number;
  private readonly maxClusterEndpoints: number;

  constructor(redisUrl: string, options: RedisReplayStoreOptions = {}) {
    const parsed = parseRedisUrl(redisUrl);
    this.target = parsed;
    const poolSize = validPoolSize(options.poolSize ?? configuredPoolSize());
    this.poolSize = poolSize;
    this.maxPendingPerConnection = validPendingLimit(
      options.maxPendingPerConnection ?? configuredPendingLimit(),
    );
    this.commandTimeoutMs = validCommandTimeout(
      options.commandTimeoutMs ?? configuredCommandTimeout(),
    );
    this.maxClusterEndpoints = validClusterEndpointLimit(
      options.maxClusterEndpoints ?? configuredClusterEndpointLimit(),
    );
    this.prefix = options.prefix ?? 'lattice:replay:v1:';
    if (!/^[A-Za-z0-9:_-]{1,128}$/.test(this.prefix)) {
      throw new Error('Redis replay key prefix contains unsupported characters');
    }
    this.clients = Array.from({ length: poolSize }, () => new RedisConnection(parsed, this.maxPendingPerConnection, this.commandTimeoutMs));
  }

  async claim(key: string, ttlMs: number): Promise<boolean> {
    if (!Number.isSafeInteger(ttlMs) || ttlMs <= 0 || ttlMs > 86_400_000) {
      throw new Error('Replay TTL must be between 1ms and 24h');
    }
    // Avoid placing agent identifiers/nonces in an infrastructure-visible key.
    const digest = crypto.createHash('sha256').update(key, 'utf8').digest('hex');
    const redisKey = `${this.prefix}${digest}`;
    const response = await this.commandWithClusterRedirect(redisKey, ['SET', redisKey, '1', 'NX', 'PX', String(ttlMs)]);
    if (response === null) return false;
    if (response !== 'OK') throw new Error('Unexpected Redis replay response');
    return true;
  }

  close(): void {
    for (const client of this.clients) client.close();
    for (const pool of this.clusterClients.values()) for (const client of pool) client.close();
    this.clusterClients.clear();
    this.clusterSlots.clear();
  }

  private async commandWithClusterRedirect(key: string, command: string[]): Promise<RespValue> {
    const slot = redisClusterSlot(key);
    const redirectedAddress = this.clusterSlots.get(slot);
    let client = redirectedAddress
      ? this.clusterPool(redirectedAddress)[this.next++ % this.poolSize]!
      : this.clients[this.next++ % this.clients.length]!;
    for (let attempt = 0; attempt < 3; attempt++) {
      try {
        return await client.command(command);
      } catch (error) {
        const moved = movedTarget(error instanceof Error ? error.message : String(error));
        if (!moved) throw error;
        const address = `${moved.host}:${moved.port}`;
        this.clusterSlots.set(slot, address);
        client = this.clusterPool(address, moved)[this.next++ % this.poolSize]!;
      }
    }
    throw new Error('Redis Cluster repeatedly redirected replay claim');
  }

  private clusterPool(address: string, moved?: { host: string; port: number }): RedisConnection[] {
    let pool = this.clusterClients.get(address);
    if (!pool) {
      if (this.clusterClients.size >= this.maxClusterEndpoints) {
        throw new Error(`Redis replay cluster endpoint capacity: ${this.maxClusterEndpoints}`);
      }
      const [host, portText] = address.lastIndexOf(':') >= 0
        ? [address.slice(0, address.lastIndexOf(':')), address.slice(address.lastIndexOf(':') + 1)]
        : ['', ''];
      const target = moved ?? { host, port: Number(portText) };
      pool = Array.from(
        { length: this.poolSize },
        () => new RedisConnection({ ...this.target, ...target }, this.maxPendingPerConnection, this.commandTimeoutMs),
      );
      this.clusterClients.set(address, pool);
    }
    return pool;
  }
}

/** Chooses the distributed store only when explicitly configured. */
export function replayStoreFromEnv(env: NodeJS.ProcessEnv = process.env): ReplayStore {
  const url = env.LATTICE_REPLAY_REDIS_URL?.trim();
  return url ? new RedisReplayStore(url) : new LocalReplayStore();
}

interface RedisTarget {
  secure: boolean;
  host: string;
  port: number;
  username?: string;
  password?: string;
  database: number;
}

function parseRedisUrl(value: string): RedisTarget {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error('LATTICE_REPLAY_REDIS_URL must be a redis:// or rediss:// URL');
  }
  if (url.protocol !== 'redis:' && url.protocol !== 'rediss:') {
    throw new Error('LATTICE_REPLAY_REDIS_URL must use redis:// or rediss://');
  }
  if (!url.hostname) throw new Error('LATTICE_REPLAY_REDIS_URL must include a host');
  const port = url.port ? Number(url.port) : 6379;
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) throw new Error('Invalid Redis port');
  const databaseText = url.pathname.replace(/^\//, '') || '0';
  if (!/^[0-9]+$/.test(databaseText)) throw new Error('Redis database must be numeric');
  const database = Number(databaseText);
  if (!Number.isSafeInteger(database) || database < 0 || database > 15) throw new Error('Redis database must be between 0 and 15');
  return {
    secure: url.protocol === 'rediss:',
    host: url.hostname,
    port,
    username: url.username ? decodeURIComponent(url.username) : undefined,
    password: url.password ? decodeURIComponent(url.password) : undefined,
    database,
  };
}

function configuredPoolSize(): number {
  const raw = process.env.LATTICE_REPLAY_REDIS_POOL_SIZE?.trim();
  if (!raw) return 16;
  if (!/^[0-9]+$/.test(raw)) throw new Error('LATTICE_REPLAY_REDIS_POOL_SIZE must be an integer');
  return validPoolSize(Number(raw));
}

function validPoolSize(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > 64) {
    throw new Error('Redis replay pool size must be between 1 and 64');
  }
  return value;
}

function configuredPendingLimit(): number {
  const raw = process.env.LATTICE_REPLAY_REDIS_MAX_PENDING_PER_CONNECTION?.trim();
  if (!raw) return 512;
  if (!/^[0-9]+$/.test(raw)) throw new Error('LATTICE_REPLAY_REDIS_MAX_PENDING_PER_CONNECTION must be an integer');
  return validPendingLimit(Number(raw));
}

function validPendingLimit(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > 4_096) {
    throw new Error('Redis replay max pending per connection must be between 1 and 4096');
  }
  return value;
}

function configuredCommandTimeout(): number {
  const raw = process.env.LATTICE_REPLAY_REDIS_COMMAND_TIMEOUT_MS?.trim();
  if (!raw) return 5_000;
  if (!/^[0-9]+$/.test(raw)) throw new Error('LATTICE_REPLAY_REDIS_COMMAND_TIMEOUT_MS must be an integer');
  return validCommandTimeout(Number(raw));
}

function validCommandTimeout(value: number): number {
  if (!Number.isSafeInteger(value) || value < 100 || value > 10_000) {
    throw new Error('Redis replay command timeout must be between 100 and 10000ms');
  }
  return value;
}

function configuredClusterEndpointLimit(): number {
  const raw = process.env.LATTICE_REPLAY_REDIS_MAX_CLUSTER_ENDPOINTS?.trim();
  if (!raw) return 16;
  if (!/^[0-9]+$/.test(raw)) throw new Error('LATTICE_REPLAY_REDIS_MAX_CLUSTER_ENDPOINTS must be an integer');
  return validClusterEndpointLimit(Number(raw));
}

function validClusterEndpointLimit(value: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > 64) {
    throw new Error('Redis replay max cluster endpoints must be between 1 and 64');
  }
  return value;
}

function movedTarget(message: string): { host: string; port: number } | null {
  const match = /\bMOVED\s+\d+\s+(\[[^\]]+\]|[^:\s]+):(\d+)\b/.exec(message);
  if (!match) return null;
  const host = match[1]!.replace(/^\[|\]$/g, '');
  const port = Number(match[2]);
  return Number.isSafeInteger(port) && port >= 1 && port <= 65_535 ? { host, port } : null;
}

function redisClusterSlot(key: string): number {
  const tagStart = key.indexOf('{');
  const tagEnd = tagStart >= 0 ? key.indexOf('}', tagStart + 1) : -1;
  const source = tagEnd > tagStart + 1 ? key.slice(tagStart + 1, tagEnd) : key;
  let crc = 0;
  for (const byte of Buffer.from(source, 'utf8')) {
    crc ^= byte << 8;
    for (let bit = 0; bit < 8; bit++) crc = (crc & 0x8000) ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
  }
  return crc & 0x3fff;
}

type RespValue = string | number | null;
interface PendingResponse {
  resolve: (value: RespValue) => void;
  reject: (error: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}
type RedisSocket = net.Socket | tls.TLSSocket;

class RedisConnection {
  private socket: RedisSocket | undefined;
  private connecting: Promise<void> | undefined;
  private buffer = Buffer.alloc(0);
  private readonly pending: PendingResponse[] = [];

  constructor(
    private readonly target: RedisTarget,
    private readonly maxPending: number,
    private readonly commandTimeoutMs: number,
  ) {}

  async command(parts: string[]): Promise<RespValue> {
    await this.ensureConnected();
    const socket = this.socket;
    if (!socket || socket.destroyed) throw new Error('Redis replay connection unavailable');
    return this.send(socket, parts);
  }

  close(): void {
    this.socket?.destroy();
    this.socket = undefined;
    this.rejectPending(new Error('Redis replay store closed'));
  }

  private async ensureConnected(): Promise<void> {
    if (this.socket && !this.socket.destroyed) return;
    if (!this.connecting) this.connecting = this.connect().finally(() => { this.connecting = undefined; });
    return this.connecting;
  }

  private connect(): Promise<void> {
    return new Promise((resolve, reject) => {
      const socket: RedisSocket = this.target.secure
        ? tls.connect({ host: this.target.host, port: this.target.port, servername: this.target.host, rejectUnauthorized: true })
        : net.connect({ host: this.target.host, port: this.target.port });
      let settled = false;
      const fail = (error: Error) => {
        if (!settled) { settled = true; reject(error); }
        if (this.socket === socket) this.socket = undefined;
        this.rejectPending(error);
      };
      socket.on('data', chunk => this.consume(Buffer.from(chunk)));
      socket.on('error', error => fail(new Error(`Redis replay connection failed: ${error.message}`)));
      socket.on('close', () => fail(new Error('Redis replay connection closed')));
      socket.setTimeout(this.commandTimeoutMs, () => {
        socket.destroy(new Error('Redis replay connection timed out'));
      });
      socket.once(this.target.secure ? 'secureConnect' : 'connect', () => {
        this.socket = socket;
        socket.setTimeout(0);
        void this.initialize().then(() => {
          if (!settled) { settled = true; resolve(); }
        }).catch(error => {
          socket.destroy();
          fail(error instanceof Error ? error : new Error(String(error)));
        });
      });
    });
  }

  private async initialize(): Promise<void> {
    if (this.target.password) {
      const auth = this.target.username
        ? ['AUTH', this.target.username, this.target.password]
        : ['AUTH', this.target.password];
      if (await this.commandRaw(auth) !== 'OK') throw new Error('Redis replay authentication failed');
    }
    if (this.target.database !== 0 && await this.commandRaw(['SELECT', String(this.target.database)]) !== 'OK') {
      throw new Error('Redis replay database selection failed');
    }
  }

  private commandRaw(parts: string[]): Promise<RespValue> {
    const socket = this.socket;
    if (!socket || socket.destroyed) return Promise.reject(new Error('Redis replay connection unavailable'));
    return this.send(socket, parts);
  }

  private send(socket: RedisSocket, parts: string[]): Promise<RespValue> {
    if (this.pending.length >= this.maxPending) {
      return Promise.reject(new Error(`Redis replay connection backpressure: ${this.maxPending} pending commands`));
    }
    return new Promise<RespValue>((resolve, reject) => {
      const timer = setTimeout(() => {
        // RESP is ordered. Removing only one timed-out command would desync
        // later replies, so close this connection and fail every pending claim.
        socket.destroy(new Error('Redis replay command timed out'));
      }, this.commandTimeoutMs);
      const pending: PendingResponse = { resolve, reject, timer };
      this.pending.push(pending);
      socket.write(encodeCommand(parts), error => {
        if (!error) return;
        const index = this.pending.indexOf(pending);
        if (index >= 0) this.pending.splice(index, 1);
        clearTimeout(timer);
        reject(new Error(`Redis replay write failed: ${error.message}`));
      });
    });
  }

  private consume(chunk: Buffer): void {
    if (this.buffer.length + chunk.length > MAX_REDIS_RESPONSE_BUFFER_BYTES) {
      this.socket?.destroy(new Error('Redis replay response buffer exceeded limit'));
      return;
    }
    this.buffer = Buffer.concat([this.buffer, chunk]);
    for (;;) {
      const parsed = parseResp(this.buffer);
      if (!parsed) return;
      this.buffer = this.buffer.subarray(parsed.bytes);
      const pending = this.pending.shift();
      if (!pending) continue;
      clearTimeout(pending.timer);
      if (parsed.error) pending.reject(new Error(`Redis replay command failed: ${parsed.error}`));
      else pending.resolve(parsed.value);
    }
  }

  private rejectPending(error: Error): void {
    while (this.pending.length) {
      const pending = this.pending.shift()!;
      clearTimeout(pending.timer);
      pending.reject(error);
    }
  }
}

function encodeCommand(parts: string[]): Buffer {
  const chunks: Buffer[] = [Buffer.from(`*${parts.length}\r\n`, 'utf8')];
  for (const part of parts) {
    const bytes = Buffer.from(part, 'utf8');
    chunks.push(Buffer.from(`$${bytes.length}\r\n`, 'utf8'), bytes, Buffer.from('\r\n', 'utf8'));
  }
  return Buffer.concat(chunks);
}

function parseResp(buffer: Buffer): { bytes: number; value: RespValue; error?: string } | null {
  if (buffer.length < 3) return null;
  const lineEnd = buffer.indexOf('\r\n');
  if (lineEnd < 0) return null;
  const type = String.fromCharCode(buffer[0]!);
  const line = buffer.subarray(1, lineEnd).toString('utf8');
  if (type === '+' || type === '-') return { bytes: lineEnd + 2, value: line, ...(type === '-' ? { error: line } : {}) };
  if (type === ':') {
    const value = Number(line);
    return Number.isSafeInteger(value) ? { bytes: lineEnd + 2, value } : { bytes: lineEnd + 2, value: line, error: 'invalid integer response' };
  }
  if (type !== '$') return { bytes: lineEnd + 2, value: line, error: 'unsupported Redis response type' };
  const length = Number(line);
  if (!Number.isSafeInteger(length) || length < -1) return { bytes: lineEnd + 2, value: line, error: 'invalid bulk response' };
  if (length === -1) return { bytes: lineEnd + 2, value: null };
  const end = lineEnd + 2 + length + 2;
  if (buffer.length < end) return null;
  if (buffer[end - 2] !== 13 || buffer[end - 1] !== 10) return { bytes: end, value: '', error: 'invalid bulk terminator' };
  return { bytes: end, value: buffer.subarray(lineEnd + 2, lineEnd + 2 + length).toString('utf8') };
}
