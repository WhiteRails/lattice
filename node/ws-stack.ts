/**
 * Helpers for Lattice overlay WebSocket binds (pure WS vs WSS mounted on HTTPS).
 */
import * as fs from 'fs';
import * as https from 'https';
import * as http from 'http';
import type { Server as HttpLikeServer } from 'http';
import { WebSocketServer } from 'ws';
import type { LatticeNodeYaml } from './node-config';

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

/** Relay / gateway ingress: listens on WS or WSS. */
export function bindOverlayWebSocketServer(host: string, port: number, tls: LatticeNodeYaml['tls']): BoundWebSocketRelay {
  const creds = readHttpsTlsCredentials(tls);
  if (creds) {
    const srv = https.createServer({ ...creds });
    const wss = new WebSocketServer({ server: srv });
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

  const wss = new WebSocketServer({ port, host });
  return {
    wss,
    close: () => wss.close(),
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
): BoundHttpMaybeTls {
  const creds = readHttpsTlsCredentials(tls);
  if (creds) {
    const srv = https.createServer({ ...creds }, listener);
    srv.listen(port, host);
    return { server: srv, close: () => srv.close() };
  }

  const srv = http.createServer(listener);
  srv.listen(port, host);
  return { server: srv, close: () => srv.close() };
}
