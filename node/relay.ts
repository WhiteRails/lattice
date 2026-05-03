import { WebSocketServer, WebSocket } from 'ws';
import { OverlayMessage, signOverlayMessage, verifyOverlayMessage } from './message';
import { loadCA } from './state';
import chalk from 'chalk';

export const DEFAULT_RELAY_PORT = 8888;

export class RelayNode {
  private wss: WebSocketServer;
  
  // Fake Federated Registry for the testnet
  // Maps destination -> Gateway WS URL
  private registry: Record<string, string> = {
    'lp://echo.lattice': 'ws://127.0.0.1:8889',
    'lp://github.lattice': 'ws://127.0.0.1:8890',
    'lp://gmail.lattice': 'ws://127.0.0.1:8891',
    'lp://browser.lattice': 'ws://127.0.0.1:8892',
  };

  constructor(port = DEFAULT_RELAY_PORT) {
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
    if (!verifyOverlayMessage(msg, overlaySecret)) {
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

    // Connect to the Gateway
    const gatewayWs = new WebSocket(targetUrl);
    
    gatewayWs.on('open', () => {
      gatewayWs.send(JSON.stringify(msg));
    });

    gatewayWs.on('message', (gwData) => {
      // Forward response back to the Entry Node
      const response: OverlayMessage = JSON.parse(gwData.toString());
      if (!verifyOverlayMessage(response, overlaySecret)) {
        this.sendError(clientWs, msg, 'Unauthenticated gateway response');
        gatewayWs.close();
        return;
      }
      response.trace.push('relay');
      if (clientWs.readyState === WebSocket.OPEN) {
        clientWs.send(JSON.stringify(response));
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
      trace: [...req.trace]
    }, loadCA().overlaySecret);
    if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(res));
  }
}
