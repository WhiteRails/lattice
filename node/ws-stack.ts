/**
 * Helpers for Lattice overlay WebSocket binds (pure WS vs WSS mounted on HTTPS).
 */
import * as fs from 'fs';
import * as https from 'https';
import * as http from 'http';
import type { Server as HttpLikeServer } from 'http';
import { WebSocketServer } from 'ws';
import type { LatticeNodeYaml } from './node-config';
import { MAX_OVERLAY_FRAME_BYTES } from './message';
import { inboundNetworkLimitsFromEnv, type InboundNetworkLimits } from './network-limits';

export type WsCloseFn = () => void;

/** Returns null if tls section missing one of cert/key. */
export function readHttpsTlsCredentials(tls: LatticeNodeYaml['tls']) {
  if (!tls?.certFile?.trim() || !tls?.keyFile?.trim()) return null;
  return {
    cert: fs.readFileSync(tls.certFile.trim()),
    key: fs.readFileSync(tls.keyFile.trim()),
    ca: tls.caFile?.trim() ? fs.readFileSync(tls.caFile.trim()) : undefined,
  };
}

/** Optional TLS for outbound `ws`/`wss` upgrades (explicit CA pinning). */
export function wsTlsClientOptions(cfg: LatticeNodeYaml | null): import('tls').SecureContextOptions | undefined {
  const c = cfg?.tls;
  if (!c?.caFile?.trim()) return undefined;
  return { ca: fs.readFileSync(c.caFile.trim()) };
}

export interface BoundWebSocketRelay {
  wss: WebSocketServer;
  httpServer?: HttpLikeServer | https.Server | null;
  close: WsCloseFn;
}

type BoundedHttpServer = http.Server | https.Server;

/** Apply the shared cell socket/time budgets to an HTTP or HTTPS listener. */
export function applyInboundHttpNetworkLimits(server: BoundedHttpServer, limits: InboundNetworkLimits): void {
  server.maxConnections = limits.maxConnections;
  // Matches the overlay/header forwarding schema. Node's default permits a far
  // larger cardinality than a cell should parse for one request.
  server.maxHeadersCount = 100;
  server.headersTimeout = limits.headersTimeoutMs;
  server.requestTimeout = limits.requestTimeoutMs;
  // Keep-alive connections without an active request cannot consume a socket
  // forever.  The WebSocket upgrade path gets its own idle timeout below.
  server.keepAliveTimeout = Math.min(5_000, limits.requestTimeoutMs);
}

function attachBoundedWebSocketServer(server: BoundedHttpServer, limits: InboundNetworkLimits): WebSocketServer {
  let activeConnections = 0;
  const wss = new WebSocketServer({
    server,
    maxPayload: MAX_OVERLAY_FRAME_BYTES,
    verifyClient: (_info, done) => {
      if (activeConnections >= limits.maxConnections) {
        done(false, 503, 'Lattice overlay connection capacity reached');
        return;
      }
      activeConnections++;
      done(true);
    },
  });
  wss.on('connection', ws => {
    // A WebSocket upgrade is no longer subject to HTTP request timeouts.
    // Terminate an inactive connection to retain a finite FD budget even if a
    // peer never sends a frame or a close handshake.
    const socket = (ws as unknown as { _socket?: import('net').Socket })._socket;
    socket?.setTimeout(limits.websocketIdleTimeoutMs, () => ws.terminate());
    ws.once('close', () => {
      activeConnections = Math.max(0, activeConnections - 1);
    });
  });
  return wss;
}

/** Relay / gateway ingress: listens on WS or WSS. */
export function bindOverlayWebSocketServer(
  host: string,
  port: number,
  tls: LatticeNodeYaml['tls'],
  limits: InboundNetworkLimits = inboundNetworkLimitsFromEnv(),
  requestListener?: http.RequestListener,
): BoundWebSocketRelay {
  const creds = readHttpsTlsCredentials(tls);
  const srv = creds ? https.createServer({ ...creds }, requestListener) : http.createServer(requestListener);
  applyInboundHttpNetworkLimits(srv, limits);
  const wss = attachBoundedWebSocketServer(srv, limits);
  srv.listen(port, host);
  return {
    wss,
    httpServer: srv,
    close: () => {
      wss.close();
      srv.close();
    },
  };
}

export interface BoundHttpMaybeTls {
  server: HttpLikeServer | https.Server;
  close: () => void;
}

export function bindHttpListen(
  listener: http.RequestListener,
  host: string,
  port: number,
  tls: LatticeNodeYaml['tls'],
  limits: InboundNetworkLimits = inboundNetworkLimitsFromEnv(),
): BoundHttpMaybeTls {
  const creds = readHttpsTlsCredentials(tls);
  if (creds) {
    const srv = https.createServer({ ...creds }, listener);
    applyInboundHttpNetworkLimits(srv, limits);
    srv.listen(port, host);
    return { server: srv, close: () => srv.close() };
  }

  const srv = http.createServer(listener);
  applyInboundHttpNetworkLimits(srv, limits);
  srv.listen(port, host);
  return { server: srv, close: () => srv.close() };
}
