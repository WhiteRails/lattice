import * as http from 'http';
import * as crypto from 'crypto';
import { WebSocket } from 'ws';
import { OverlayMessage, signOverlayMessage, verifyOverlayMessage } from './message';
import { isRevoked, loadAgent, loadCA } from './state';
import { hashRequestBody, requestSignaturePayload, verifySignature } from '../core/identity';
import chalk from 'chalk';

export const DEFAULT_ENTRY_PORT = 7777;

export class EntryNode {
  private server: http.Server;
  // In a real system, we'd look up the relay from a Federated Registry.
  // For MVP, we hardcode to our local testnet relay.
  private relayUrl = 'ws://127.0.0.1:8888';

  constructor(port = DEFAULT_ENTRY_PORT) {
    this.server = http.createServer((req, res) => this.handleHttp(req, res));
    this.server.listen(port, '127.0.0.1', () =>
      console.log(chalk.cyan(`[EntryNode]`) + ` Listening for agents on 127.0.0.1:${port}`)
    );
  }

  private handleHttp(req: http.IncomingMessage, res: http.ServerResponse) {
    const agent = this.agentName(req);
    if (isRevoked(agent)) {
      res.writeHead(403);
      res.end(JSON.stringify({ error: 'Agent revoked' }));
      return;
    }

    const host = (req.headers.host ?? '').split(':')[0];
    const resource = `lp://${host}`;

    // Read full body
    const chunks: Buffer[] = [];
    req.on('data', d => chunks.push(d));
    req.on('end', () => {
      const rawBody = Buffer.concat(chunks);
      const identity = this.verifyAgentRequest(req, agent, rawBody);
      if (!identity.ok) {
        res.writeHead(identity.status, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: identity.error }));
        return;
      }

      const body = rawBody.toString('base64');
      
      const msg = signOverlayMessage({
        id: crypto.randomBytes(8).toString('hex'),
        type: 'request',
        source: agent,
        destination: resource,
        payload: {
          method: req.method,
          url: req.url,
          headers: req.headers as Record<string, string>,
          body
        },
        trace: ['entry']
      }, loadCA().overlaySecret);

      console.log(chalk.cyan(`[EntryNode]`) + ` Routing ${req.method} ${req.url} -> ${resource} via Relay`);
      this.forwardToRelay(msg, res);
    });
  }

  private forwardToRelay(msg: OverlayMessage, res: http.ServerResponse) {
    const ws = new WebSocket(this.relayUrl);
    
    ws.on('open', () => {
      ws.send(JSON.stringify(msg));
    });

    ws.on('message', (data) => {
      const response: OverlayMessage = JSON.parse(data.toString());
      if (!verifyOverlayMessage(response, loadCA().overlaySecret)) {
        res.writeHead(502, { 'content-type': 'application/json' });
        res.end(JSON.stringify({ error: 'Unauthenticated overlay response' }));
        ws.close();
        return;
      }
      if (response.id === msg.id && response.type === 'response') {
        res.writeHead(response.payload.status ?? 502, response.payload.headers);
        if (response.payload.body) {
          res.end(Buffer.from(response.payload.body, 'base64'));
        } else {
          res.end();
        }
        ws.close();
      }
    });

    ws.on('error', (err) => {
      console.error(chalk.red(`[EntryNode]`) + ` Relay connection failed: ${err.message}`);
      res.writeHead(502);
      res.end(JSON.stringify({ error: 'Overlay network unavailable' }));
    });
  }

  private agentName(req: http.IncomingMessage): string {
    return (req.headers['x-lattice-agent'] as string) ?? process.env.LATTICE_AGENT ?? 'unknown';
  }

  private verifyAgentRequest(
    req: http.IncomingMessage,
    agent: string,
    body: Buffer,
  ): { ok: true } | { ok: false; status: number; error: string } {
    let agentState;
    try {
      agentState = loadAgent(agent);
    } catch {
      return { ok: false, status: 401, error: 'Unknown agent identity' };
    }

    const signature = singleHeader(req.headers['x-lattice-signature']);
    const timestamp = singleHeader(req.headers['x-lattice-timestamp']);
    if (!signature || !timestamp) {
      return { ok: false, status: 401, error: 'Missing Lattice agent signature' };
    }

    const ageMs = Math.abs(Date.now() - new Date(timestamp).getTime());
    if (!Number.isFinite(ageMs) || ageMs > 5 * 60_000) {
      return { ok: false, status: 401, error: 'Stale Lattice agent signature' };
    }

    const payload = requestSignaturePayload({
      method: req.method,
      host: singleHeader(req.headers.host),
      url: req.url,
      timestamp,
      bodyHash: hashRequestBody(body),
    });

    const publicKey = agentState.publicKey ?? agentState.cert?.public_key;
    if (!publicKey || !verifySignature(payload, signature, publicKey)) {
      return { ok: false, status: 401, error: 'Invalid Lattice agent signature' };
    }

    return { ok: true };
  }
}

function singleHeader(value: string | string[] | undefined): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}
