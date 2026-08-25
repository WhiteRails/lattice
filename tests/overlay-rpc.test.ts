import { afterEach, describe, expect, it } from 'vitest';
import { WebSocketServer } from 'ws';
import { OverlayRpcClient, OverlayRpcPool, overlayRpcPoolOptionsFromEnv } from '../node/overlay-rpc';
import type { OverlayMessage } from '../node/message';

const closers: Array<() => Promise<void>> = [];

afterEach(async () => {
  while (closers.length) await closers.pop()!();
});

async function startServer(onMessage: (ws: import('ws').WebSocket, message: OverlayMessage) => void): Promise<string> {
  const server = new WebSocketServer({ port: 0, host: '127.0.0.1' });
  server.on('connection', ws => {
    ws.on('message', raw => onMessage(ws, JSON.parse(raw.toString()) as OverlayMessage));
  });
  await new Promise<void>((resolve, reject) => {
    server.once('listening', resolve);
    server.once('error', reject);
  });
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Expected TCP server address');
  closers.push(() => new Promise(resolve => server.close(() => resolve())));
  return `ws://127.0.0.1:${address.port}`;
}

function request(id: string): OverlayMessage {
  return {
    id,
    type: 'request',
    source: 'entry',
    destination: 'lp://echo.lattice',
    payload: { method: 'GET', url: '/' },
    trace: [],
  };
}

describe('OverlayRpcClient', () => {
  it('multiplexes concurrent overlay requests over one persistent connection', async () => {
    const connections = new Set<object>();
    const url = await startServer((ws, message) => {
      connections.add(ws);
      setTimeout(() => ws.send(JSON.stringify({
        ...message,
        type: 'response',
        payload: { status: 200 },
      })), Number(message.id.slice(1)) % 3);
    });
    const client = new OverlayRpcClient(url);
    closers.push(async () => client.close());

    const responses = await Promise.all(
      Array.from({ length: 64 }, (_, i) => client.request(request(`r${i}`))),
    );

    expect(responses.map(r => r.id).sort()).toEqual(Array.from({ length: 64 }, (_, i) => `r${i}`).sort());
    expect(connections.size).toBe(1);
    expect(client.inFlight).toBe(0);
  });

  it('rejects failed in-flight work and reconnects for the next request', async () => {
    let connections = 0;
    const url = await startServer((ws, message) => {
      connections++;
      if (connections === 1) {
        ws.close();
        return;
      }
      ws.send(JSON.stringify({ ...message, type: 'response', payload: { status: 200 } }));
    });
    const client = new OverlayRpcClient(url);
    closers.push(async () => client.close());

    await expect(client.request(request('first'))).rejects.toThrow(/closed|send failed/i);
    await expect(client.request(request('second'))).resolves.toMatchObject({ id: 'second', type: 'response' });
    expect(connections).toBe(2);
  });

  it('applies bounded backpressure before accepting unbounded in-flight work', async () => {
    const url = await startServer(() => {
      // Intentionally withhold a response.
    });
    const client = new OverlayRpcClient(url, { maxPending: 1, requestTimeoutMs: 10_000 });
    closers.push(async () => client.close());

    const first = client.request(request('first'));
    await expect(client.request(request('second'))).rejects.toThrow(/backpressure/i);
    client.close();
    await expect(first).rejects.toThrow(/closed/i);
  });

  it('rejects an oversized response frame from a remote overlay endpoint', async () => {
    const url = await startServer(ws => {
      ws.send('x'.repeat(1_048_577));
    });
    const client = new OverlayRpcClient(url, { requestTimeoutMs: 10_000 });
    closers.push(async () => client.close());

    await expect(client.request(request('oversized'))).rejects.toThrow(/closed|payload|frame/i);
    expect(client.inFlight).toBe(0);
  });
});

describe('OverlayRpcPool', () => {
  it('validates process-level pool budgets before a cell starts', () => {
    expect(overlayRpcPoolOptionsFromEnv({
      LATTICE_OVERLAY_RPC_MAX_CLIENTS: '64',
      LATTICE_OVERLAY_RPC_MAX_PENDING: '128',
      LATTICE_OVERLAY_RPC_MAX_PENDING_PER_CONNECTION: '32',
    })).toMatchObject({ maxClients: 64, maxTotalPending: 128, maxPending: 32 });
    expect(() => overlayRpcPoolOptionsFromEnv({ LATTICE_OVERLAY_RPC_MAX_PENDING: 'abc' })).toThrow(/integer/i);
    expect(() => overlayRpcPoolOptionsFromEnv({
      LATTICE_OVERLAY_RPC_MAX_PENDING: '32',
      LATTICE_OVERLAY_RPC_MAX_PENDING_PER_CONNECTION: '64',
    })).toThrow(/cannot exceed/i);
  });

  it('caps aggregate work across endpoint connections', async () => {
    const url = await startServer(() => {
      // Intentionally withhold a response.
    });
    const pool = new OverlayRpcPool({ maxTotalPending: 1, requestTimeoutMs: 10_000 });
    closers.push(async () => pool.close());

    const first = pool.request(url, request('first'));
    expect(pool.inFlight()).toBe(1);
    await expect(pool.request(url, request('second'))).rejects.toThrow(/pool backpressure/i);
    pool.close();
    await expect(first).rejects.toThrow(/closed/i);
    expect(pool.inFlight()).toBe(0);
  });

  it('evicts an idle least-recently-used endpoint rather than growing unbounded', async () => {
    const firstUrl = await startServer((ws, message) => ws.send(JSON.stringify({ ...message, type: 'response', payload: { status: 200 } })));
    const secondUrl = await startServer((ws, message) => ws.send(JSON.stringify({ ...message, type: 'response', payload: { status: 200 } })));
    const pool = new OverlayRpcPool({ maxClients: 1 });
    closers.push(async () => pool.close());

    await expect(pool.request(firstUrl, request('first'))).resolves.toMatchObject({ id: 'first' });
    await expect(pool.request(secondUrl, request('second'))).resolves.toMatchObject({ id: 'second' });
    expect(pool.clientCount).toBe(1);
  });
});
