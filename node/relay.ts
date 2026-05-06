import { WebSocketServer, WebSocket } from 'ws';
import { OverlayMessage, signOverlayMessage, verifyOverlayMessage } from './message';
import { loadCA, getOrCreateOverlayKeyPair } from './state';
import { SessionManager } from './session';
import chalk from 'chalk';

export const DEFAULT_RELAY_PORT = 8888;

export class RelayNode {
  private wss: WebSocketServer;
  private myPublicKey: string;
  private upstreamMgr: SessionManager;   // sessions with entry nodes
  private downstreamMgr: SessionManager; // sessions with gateway nodes

  // Fake Federated Registry for the testnet
  // Maps destination -> Gateway WS URL
  private registry: Record<string, string> = {
    'lp://echo.lattice': 'ws://127.0.0.1:8889',
    'lp://github.lattice': 'ws://127.0.0.1:8890',
    'lp://gmail.lattice': 'ws://127.0.0.1:8891',
    'lp://browser.lattice': 'ws://127.0.0.1:8892',
  };

  constructor(port = DEFAULT_RELAY_PORT) {
    const relayKeyPair = getOrCreateOverlayKeyPair();
    this.myPublicKey = relayKeyPair.publicKey;
    this.upstreamMgr = new SessionManager('relay-upstream', relayKeyPair.privateKey);
    this.downstreamMgr = new SessionManager('relay-downstream', relayKeyPair.privateKey);

    this.wss = new WebSocketServer({ port, host: '127.0.0.1' });
    
    this.wss.on('connection', (ws) => {
      ws.on('message', (data) => this.handleMessage(ws, data.toString()));
    });

    console.log(chalk.magenta(`[RelayNode]`) + ` Listening for overlay traffic on 127.0.0.1:${port}`);
  }

  private handleMessage(clientWs: WebSocket, data: string) {
    let msg: OverlayMessage;
    try {
      msg = JSON.parse(data);
    } catch { return; }

    const overlaySecret = loadCA().overlaySecret;

    // Verify inbound from entry: use per-peer session key if entry provided its pubkey
    const entryVerifyKey = msg.source_pubkey
      ? this.upstreamMgr.getSessionKey(msg.source, msg.source_pubkey)
      : overlaySecret;
    if (!verifyOverlayMessage(msg, entryVerifyKey)) {
      this.sendError(clientWs, msg, 'Unauthenticated overlay request');
      return;
    }

    msg.trace.push('relay');

    console.log(chalk.magenta(`[RelayNode]`) + ` Routing ${msg.id} -> ${msg.destination}`);

    const targetUrl = this.registry[msg.destination];
    if (!targetUrl) {
      this.sendError(clientWs, msg, `Host not found in registry: ${msg.destination}`);
      return;
    }

    // Re-sign the message for the downstream gateway with relay's own pubkey
    const downstreamMsg = signOverlayMessage({
      ...msg,
      auth: undefined,
      source_pubkey: this.myPublicKey,
    }, overlaySecret);

    // Connect to the Gateway
    const gatewayWs = new WebSocket(targetUrl);

    gatewayWs.on('open', () => {
      gatewayWs.send(JSON.stringify(downstreamMsg));
    });

    gatewayWs.on('message', (gwData) => {
      // Forward response back to the Entry Node
      const response: OverlayMessage = JSON.parse(gwData.toString());
      // Verify gateway response: use per-peer key if gateway provided its pubkey
      const gwVerifyKey = response.source_pubkey
        ? this.downstreamMgr.getSessionKey(response.source, response.source_pubkey)
        : overlaySecret;
      if (!verifyOverlayMessage(response, gwVerifyKey)) {
        this.sendError(clientWs, msg, 'Unauthenticated gateway response');
        gatewayWs.close();
        return;
      }
      response.trace.push('relay');
      // Re-sign for upstream entry with relay's pubkey
      const upstreamResponse = signOverlayMessage({
        ...response,
        auth: undefined,
        source_pubkey: this.myPublicKey,
      }, overlaySecret);
      if (clientWs.readyState === WebSocket.OPEN) {
        clientWs.send(JSON.stringify(upstreamResponse));
      }
      gatewayWs.close();
    });

    gatewayWs.on('error', (err) => {
      this.sendError(clientWs, msg, `Gateway unreachable: ${err.message}`);
    });
  }

  private sendError(ws: WebSocket, req: OverlayMessage, error: string) {
    const res = signOverlayMessage({
      id: req.id,
      type: 'response',
      source: 'relay',
      destination: req.source,
      payload: { status: 502, headers: { 'content-type': 'application/json' }, body: Buffer.from(JSON.stringify({ error })).toString('base64') },
      trace: [...req.trace],
      source_pubkey: this.myPublicKey,
    }, loadCA().overlaySecret);
    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(res));
  }
}
