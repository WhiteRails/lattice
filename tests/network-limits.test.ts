import { describe, expect, it } from 'vitest';
import { WebSocket } from 'ws';
import { DEFAULT_INBOUND_NETWORK_LIMITS, inboundNetworkLimitsFromEnv } from '../node/network-limits';
import { bindHttpListen, bindOverlayWebSocketServer } from '../node/ws-stack';

function onceOpen(ws: WebSocket): Promise<void> {
  return new Promise((resolve, reject) => {
    ws.once('open', resolve);
    ws.once('error', reject);
  });
}

describe('inbound network limits', () => {
  it('uses finite, conservative defaults for every public role', () => {
    expect(inboundNetworkLimitsFromEnv({})).toEqual(DEFAULT_INBOUND_NETWORK_LIMITS);
  });

  it('accepts bounded per-cell overrides', () => {
    expect(inboundNetworkLimitsFromEnv({
      LATTICE_MAX_INBOUND_CONNECTIONS: '4096',
      LATTICE_HTTP_HEADERS_TIMEOUT_MS: '5000',
      LATTICE_HTTP_REQUEST_TIMEOUT_MS: '30000',
      LATTICE_WEBSOCKET_IDLE_TIMEOUT_MS: '45000',
    })).toEqual({
      maxConnections: 4096,
      headersTimeoutMs: 5000,
      requestTimeoutMs: 30000,
      websocketIdleTimeoutMs: 45000,
    });
  });

  it('refuses invalid or effectively unlimited settings at startup', () => {
    expect(() => inboundNetworkLimitsFromEnv({ LATTICE_MAX_INBOUND_CONNECTIONS: '0' })).toThrow(/between/i);
    expect(() => inboundNetworkLimitsFromEnv({ LATTICE_HTTP_HEADERS_TIMEOUT_MS: 'infinite' })).toThrow(/integer/i);
    expect(() => inboundNetworkLimitsFromEnv({ LATTICE_WEBSOCKET_IDLE_TIMEOUT_MS: '3600001' })).toThrow(/between/i);
  });

  it('rejects an overlay upgrade at the socket budget before application handlers run', async () => {
    const bound = bindOverlayWebSocketServer('127.0.0.1', 0, undefined, {
      maxConnections: 1,
      headersTimeoutMs: 1_000,
      requestTimeoutMs: 1_000,
      websocketIdleTimeoutMs: 1_000,
    });
    await new Promise<void>((resolve, reject) => {
      bound.wss.once('listening', resolve);
      bound.wss.once('error', reject);
    });
    const address = bound.httpServer!.address();
    if (!address || typeof address === 'string') throw new Error('expected TCP address');
    let appConnections = 0;
    bound.wss.on('connection', () => { appConnections++; });

    const first = new WebSocket(`ws://127.0.0.1:${address.port}`);
    await onceOpen(first);
    const second = new WebSocket(`ws://127.0.0.1:${address.port}`);
    await expect(new Promise<void>((resolve, reject) => {
      second.once('open', () => reject(new Error('second connection unexpectedly admitted')));
      second.once('error', () => resolve());
    })).resolves.toBeUndefined();
    expect(appConnections).toBe(1);

    first.close();
    await new Promise(resolve => first.once('close', resolve));
    const serverClosed = new Promise<void>(resolve => bound.httpServer!.once('close', () => resolve()));
    bound.close();
    await serverClosed;
  });

  it('applies connection, header and request budgets to an HTTP entry listener', async () => {
    const bound = bindHttpListen((_req, res) => res.end(), '127.0.0.1', 0, undefined, {
      maxConnections: 321,
      headersTimeoutMs: 1_000,
      requestTimeoutMs: 2_000,
      websocketIdleTimeoutMs: 3_000,
    });
    await new Promise<void>((resolve, reject) => {
      bound.server.once('listening', resolve);
      bound.server.once('error', reject);
    });
    expect(bound.server.maxConnections).toBe(321);
    expect(bound.server.maxHeadersCount).toBe(100);
    expect(bound.server.headersTimeout).toBe(1_000);
    expect(bound.server.requestTimeout).toBe(2_000);
    const closed = new Promise<void>(resolve => bound.server.once('close', () => resolve()));
    bound.close();
    await closed;
  });
});
