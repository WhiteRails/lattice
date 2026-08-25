import { afterEach, describe, expect, it } from 'vitest';
import * as net from 'net';
import { LocalReplayStore, RedisReplayStore, replayStoreFromEnv } from '../node/replay-store';
import { entryReplayKey, gatewayReplayKey } from '../node/replay-keys';

const closers: Array<() => Promise<void>> = [];

afterEach(async () => {
  while (closers.length) await closers.pop()!();
});

async function fakeRedis(password?: string): Promise<string> {
  const claimed = new Set<string>();
  const server = net.createServer(socket => {
    let buffer = Buffer.alloc(0);
    let authenticated = !password;
    socket.on('data', raw => {
      buffer = Buffer.concat([buffer, Buffer.from(raw)]);
      for (;;) {
        const parsed = parseCommand(buffer);
        if (!parsed) return;
        buffer = buffer.subarray(parsed.bytes);
        const [command, ...args] = parsed.parts;
        if (command === 'AUTH') {
          authenticated = args.at(-1) === password;
          socket.write(authenticated ? '+OK\r\n' : '-NOAUTH invalid password\r\n');
        } else if (!authenticated) {
          socket.write('-NOAUTH authentication required\r\n');
        } else if (command === 'SET' && args[2] === 'NX' && args[3] === 'PX') {
          const key = args[0]!;
          if (claimed.has(key)) socket.write('$-1\r\n');
          else { claimed.add(key); socket.write('+OK\r\n'); }
        } else {
          socket.write('-ERR unsupported command\r\n');
        }
      }
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Expected TCP address');
  closers.push(() => new Promise(resolve => server.close(() => resolve())));
  const credentials = password ? `:${encodeURIComponent(password)}@` : '';
  return `redis://${credentials}127.0.0.1:${address.port}/0`;
}

async function fakeClusterRedirect(targetUrl: string): Promise<string> {
  const target = new URL(targetUrl);
  const server = net.createServer(socket => {
    let buffer = Buffer.alloc(0);
    socket.on('data', raw => {
      buffer = Buffer.concat([buffer, Buffer.from(raw)]);
      for (;;) {
        const parsed = parseCommand(buffer);
        if (!parsed) return;
        buffer = buffer.subarray(parsed.bytes);
        socket.write(`-MOVED 1 ${target.hostname}:${target.port}\r\n`);
      }
    });
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Expected TCP address');
  closers.push(() => new Promise(resolve => server.close(() => resolve())));
  return `redis://127.0.0.1:${address.port}/0`;
}

async function silentRedis(): Promise<string> {
  const sockets = new Set<net.Socket>();
  const server = net.createServer(socket => {
    // Accept TCP and intentionally never respond to emulate a stalled shard.
    sockets.add(socket);
    socket.once('close', () => sockets.delete(socket));
    socket.on('error', () => {});
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Expected TCP address');
  closers.push(() => new Promise(resolve => {
    for (const socket of sockets) socket.destroy();
    server.close(() => resolve());
  }));
  return `redis://127.0.0.1:${address.port}/0`;
}

async function oversizedIncompleteRedis(): Promise<string> {
  const server = net.createServer(socket => {
    socket.on('data', () => {
      // RESP bulk prefix with no terminator: it is deliberately incomplete,
      // so a client without a buffer cap would retain every byte forever.
      socket.write(Buffer.concat([Buffer.from('$999999\r\n'), Buffer.alloc(65_536, 120)]));
    });
    socket.on('error', () => {});
  });
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Expected TCP address');
  closers.push(() => new Promise(resolve => server.close(() => resolve())));
  return `redis://127.0.0.1:${address.port}/0`;
}

function parseCommand(buffer: Buffer): { parts: string[]; bytes: number } | null {
  const firstEnd = buffer.indexOf('\r\n');
  if (firstEnd < 0 || buffer[0] !== 42) return null;
  const count = Number(buffer.subarray(1, firstEnd).toString('utf8'));
  if (!Number.isSafeInteger(count) || count < 0) throw new Error('bad fake RESP array');
  let cursor = firstEnd + 2;
  const parts: string[] = [];
  for (let index = 0; index < count; index++) {
    const lengthEnd = buffer.indexOf('\r\n', cursor);
    if (lengthEnd < 0 || buffer[cursor] !== 36) return null;
    const length = Number(buffer.subarray(cursor + 1, lengthEnd).toString('utf8'));
    if (!Number.isSafeInteger(length) || length < 0) throw new Error('bad fake RESP bulk');
    const dataStart = lengthEnd + 2;
    const dataEnd = dataStart + length;
    if (buffer.length < dataEnd + 2) return null;
    parts.push(buffer.subarray(dataStart, dataEnd).toString('utf8'));
    cursor = dataEnd + 2;
  }
  return { parts, bytes: cursor };
}

describe('replay stores', () => {
  it('keeps local development replay protection fail-closed at duplicate claims', async () => {
    const store = new LocalReplayStore();
    expect(await store.claim('agent:nonce', 1_000)).toBe(true);
    expect(await store.claim('agent:nonce', 1_000)).toBe(false);
  });

  it('shares replay protection within each fleet but not across Entry and Gateway verification', async () => {
    const store = new LocalReplayStore();
    const args: [string, string, string] = ['bot1', '2026-08-25T00:00:00.000Z', 'nonce-12345678'];
    const entryKey = entryReplayKey(...args);
    const gatewayKey = gatewayReplayKey(...args);
    expect(entryKey).not.toBe(gatewayKey);
    expect(await store.claim(entryKey, 1_000)).toBe(true);
    expect(await store.claim(entryKey, 1_000)).toBe(false);
    expect(await store.claim(gatewayKey, 1_000)).toBe(true);
    expect(await store.claim(gatewayKey, 1_000)).toBe(false);
  });

  it('uses Redis SET NX PX atomically across independent gateway replicas', async () => {
    const url = await fakeRedis('secret');
    const first = new RedisReplayStore(url, { poolSize: 2 });
    const second = new RedisReplayStore(url, { poolSize: 2 });
    try {
      const results = await Promise.all([
        first.claim('agent:timestamp:nonce', 30_000),
        second.claim('agent:timestamp:nonce', 30_000),
      ]);
      expect(results.filter(Boolean)).toHaveLength(1);
    } finally {
      first.close();
      second.close();
    }
  });

  it('follows a Redis Cluster MOVED redirect and caches the destination slot', async () => {
    const shard = await fakeRedis();
    const seed = await fakeClusterRedirect(shard);
    const store = new RedisReplayStore(seed, { poolSize: 1 });
    try {
      expect(await store.claim('agent:cluster-nonce', 30_000)).toBe(true);
      expect(await store.claim('agent:cluster-nonce', 30_000)).toBe(false);
    } finally {
      store.close();
    }
  });

  it('fails closed when MOVED replies would grow cluster connection pools past the cell budget', async () => {
    const firstShard = await fakeRedis();
    const secondShard = await fakeRedis();
    const targets = [new URL(firstShard), new URL(secondShard)];
    let redirects = 0;
    const seedServer = net.createServer(socket => {
      socket.on('data', () => {
        const target = targets[Math.min(redirects++, targets.length - 1)]!;
        socket.write(`-MOVED 1 ${target.hostname}:${target.port}\r\n`);
      });
    });
    await new Promise<void>((resolve, reject) => seedServer.listen(0, '127.0.0.1', resolve).once('error', reject));
    const seedAddress = seedServer.address();
    if (!seedAddress || typeof seedAddress === 'string') throw new Error('Expected TCP address');
    closers.push(() => new Promise(resolve => seedServer.close(() => resolve())));
    const store = new RedisReplayStore(`redis://127.0.0.1:${seedAddress.port}/0`, {
      poolSize: 1,
      maxClusterEndpoints: 1,
    });
    try {
      expect(await store.claim('agent:cluster-first', 30_000)).toBe(true);
      await expect(store.claim('agent:cluster-second', 30_000)).rejects.toThrow(/endpoint capacity/i);
    } finally {
      store.close();
    }
  });

  it('bounds stalled Redis commands and fails closed instead of retaining promises', async () => {
    const store = new RedisReplayStore(await silentRedis(), {
      poolSize: 1,
      maxPendingPerConnection: 1,
      commandTimeoutMs: 100,
    });
    const first = store.claim('agent:stalled-one', 30_000);
    await new Promise(resolve => setTimeout(resolve, 20));
    await expect(store.claim('agent:stalled-two', 30_000)).rejects.toThrow(/backpressure/i);
    await expect(first).rejects.toThrow(/timed out|closed|failed/i);
    store.close();
  });

  it('drops an incomplete oversized Redis response instead of retaining an unbounded parser buffer', async () => {
    const store = new RedisReplayStore(await oversizedIncompleteRedis(), { poolSize: 1, commandTimeoutMs: 1_000 });
    try {
      await expect(store.claim('agent:oversized-resp', 30_000)).rejects.toThrow(/buffer exceeded|closed|failed/i);
    } finally {
      store.close();
    }
  });

  it('selects Redis only when the cell explicitly configures it', () => {
    expect(replayStoreFromEnv({}) instanceof LocalReplayStore).toBe(true);
    expect(replayStoreFromEnv({ LATTICE_REPLAY_REDIS_URL: 'redis://127.0.0.1:6379/0' }))
      .toBeInstanceOf(RedisReplayStore);
  });
});
