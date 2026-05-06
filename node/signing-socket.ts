import * as net from 'net';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { signData } from '../core/identity';

export const SIGNING_SOCKETS_DIR = path.join(
  process.env.LATTICE_DIR ?? path.join(process.env.HOME ?? '/tmp', '.lattice'),
  'sockets'
);

export function signingSocketPath(agentName: string): string {
  if (process.platform === 'win32') {
    return `\\\\.\\pipe\\lattice-${agentName}`;
  }
  return path.join(SIGNING_SOCKETS_DIR, `${agentName}.sock`);
}

export class SigningSocket {
  private server: net.Server;
  private socketPath: string;
  private requestCount = 0;
  private lastResetTime = Date.now();
  private readonly RATE_LIMIT = 100; // per second

  constructor(private agentName: string, private privateKey: string, private sessionToken: string) {
    this.socketPath = signingSocketPath(agentName);
    this.server = net.createServer((socket) => this.handleConnection(socket));
  }

  start(): void {
    if (process.platform !== 'win32' && !fs.existsSync(SIGNING_SOCKETS_DIR)) {
      fs.mkdirSync(SIGNING_SOCKETS_DIR, { recursive: true, mode: 0o700 });
    }
    // Remove stale socket file
    if (process.platform !== 'win32' && fs.existsSync(this.socketPath)) {
      fs.unlinkSync(this.socketPath);
    }
    // Set restrictive umask before bind to eliminate TOCTOU window
    const oldUmask = process.platform !== 'win32' ? process.umask(0o177) : 0;
    this.server.listen(this.socketPath, () => {
      if (process.platform !== 'win32') process.umask(oldUmask);
    });
  }

  stop(): void {
    this.server.close();
    if (process.platform !== 'win32' && fs.existsSync(this.socketPath)) {
      fs.unlinkSync(this.socketPath);
    }
  }

  private handleConnection(socket: net.Socket): void {
    // Step 1: Send challenge
    const challenge = crypto.randomBytes(32).toString('hex');
    socket.write(JSON.stringify({ type: 'challenge', challenge }) + '\n');

    let authenticated = false;
    let buffer = '';

    socket.on('data', (data) => {
      buffer += data.toString();
      if (buffer.length > 65536) { socket.destroy(); return; }
      const lines = buffer.split('\n');
      buffer = lines.pop() ?? '';

      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const msg = JSON.parse(line);

          if (!authenticated) {
            // Expect challenge response
            if (msg.type !== 'challenge_response') { socket.destroy(); return; }
            const expected = crypto.createHmac('sha256', this.sessionToken)
              .update(challenge).digest('hex');
            const respBuf = Buffer.from(msg.response ?? '', 'hex');
            const expBuf = Buffer.from(expected, 'hex');
            if (respBuf.length !== expBuf.length || !crypto.timingSafeEqual(respBuf, expBuf)) {
              socket.destroy(); return;
            }
            authenticated = true;
            socket.write(JSON.stringify({ type: 'authenticated' }) + '\n');
            return;
          }

          // Rate limiting
          const now = Date.now();
          if (now - this.lastResetTime > 1000) {
            this.requestCount = 0;
            this.lastResetTime = now;
          }
          if (this.requestCount >= this.RATE_LIMIT) {
            socket.write(JSON.stringify({ type: 'error', error: 'RATE_LIMITED' }) + '\n');
            return;
          }
          this.requestCount++;

          // Sign request
          if (msg.type !== 'sign') { socket.destroy(); return; }
          const signature = signData(msg.payload, this.privateKey);
          socket.write(JSON.stringify({ type: 'signature', signature }) + '\n');
        } catch {
          socket.destroy();
        }
      }
    });
  }
}
