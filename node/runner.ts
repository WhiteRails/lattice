import { spawn } from 'child_process';
import * as crypto from 'crypto';
import * as path from 'path';
import { agentExists, isRevoked, LATTICE_DIR, loadAgent } from './state';
import { SigningSocket, signingSocketPath, SIGNING_SOCKETS_DIR } from './signing-socket';
import { controlBus } from './agent-control';

export interface RunOptions {
  agentName: string;
  noInternet: boolean;
  proxyPort: number;
  command: string[];
  useDocker: boolean;
}

export async function runAgent(opts: RunOptions): Promise<void> {
  if (!agentExists(opts.agentName))
    throw new Error(`Agent '${opts.agentName}' not found. Run: lattice agent create ${opts.agentName}`);
  if (isRevoked(opts.agentName))
    throw new Error(`Agent '${opts.agentName}' is revoked`);

  return opts.useDocker ? runInDocker(opts) : runWithProxy(opts);
}

async function runWithProxy(opts: RunOptions): Promise<void> {
  const proxy = `http://127.0.0.1:${opts.proxyPort}`;
  if (opts.noInternet) {
    throw new Error('--no-internet requires an OS/container network sandbox; non-Docker mode cannot enforce it');
  }

  const agent = loadAgent(opts.agentName);
  const sessionToken = crypto.randomBytes(32).toString('hex');

  const signingSocket = new SigningSocket(opts.agentName, agent.privateKey, sessionToken);
  signingSocket.start();

  const env: NodeJS.ProcessEnv = {
    ...process.env,
    HTTP_PROXY: proxy, HTTPS_PROXY: proxy,
    http_proxy: proxy, https_proxy: proxy,
    LATTICE_AGENT: opts.agentName,
    LATTICE_SIGNING_SOCKET: signingSocketPath(opts.agentName),
    LATTICE_SESSION_TOKEN: sessionToken,
    LATTICE_DIR,
    NO_PROXY: '',
  };

  const [cmd, ...args] = opts.command;
  try {
    await spawnChild(cmd, args, env, opts.agentName);
  } finally {
    signingSocket.stop();
  }
}

async function runInDocker(opts: RunOptions): Promise<void> {
  const proxy = `http://host.docker.internal:${opts.proxyPort}`;
  const agent = loadAgent(opts.agentName);
  const sessionToken = crypto.randomBytes(32).toString('hex');

  const signingSocket = new SigningSocket(opts.agentName, agent.privateKey, sessionToken);
  signingSocket.start();

  const args = [
    'run', '--rm',
    ...(opts.noInternet ? ['--network', 'none'] : []),
    '-e', `HTTP_PROXY=${proxy}`,
    '-e', `HTTPS_PROXY=${proxy}`,
    '-e', `http_proxy=${proxy}`,
    '-e', `https_proxy=${proxy}`,
    '-e', `LATTICE_AGENT=${opts.agentName}`,
    '-e', `LATTICE_SIGNING_SOCKET=/tmp/lattice-sockets/${opts.agentName}.sock`,
    '-e', `LATTICE_SESSION_TOKEN=${sessionToken}`,
    '-v', `${SIGNING_SOCKETS_DIR}:/tmp/lattice-sockets`,
    '-v', `${process.cwd()}:/workspace`,
    '-w', '/workspace',
    detectImage(opts.command[0]),
    ...opts.command,
  ];
  const logArgs = args.map(a => a.startsWith('LATTICE_SESSION_TOKEN=') ? 'LATTICE_SESSION_TOKEN=***' : a);
  console.log(`[lattice] docker ${logArgs.join(' ')}`);
  try {
    await spawnChild('docker', args, process.env as NodeJS.ProcessEnv, opts.agentName);
  } finally {
    signingSocket.stop();
  }
}

function spawnChild(cmd: string, args: string[], env: NodeJS.ProcessEnv, agentName?: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { env, stdio: 'inherit' });
    if (agentName) controlBus.registerAgent(agentName, child);
    child.on('exit', code => {
      if (agentName) controlBus.unregisterAgent(agentName);
      code === 0 ? resolve() : reject(new Error(`Exited with code ${code}`));
    });
    child.on('error', reject);
  });
}

function detectImage(cmd: string): string {
  const m: Record<string, string> = {
    python: 'python:3.12-slim', python3: 'python:3.12-slim',
    node: 'node:20-slim', ruby: 'ruby:3.3-slim',
  };
  return m[path.basename(cmd)] ?? 'ubuntu:24.04';
}
