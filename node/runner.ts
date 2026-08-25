import { spawn, type ChildProcess } from 'child_process';
import * as crypto from 'crypto';
import * as path from 'path';
import * as fs from 'fs';
import * as os from 'os';
import { agentExists, isRevoked, LATTICE_DIR, loadAgent } from './state';
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

  return runWithNativeDaemon(opts);
}

/**
 * Native launcher for Rust agents. TypeScript only provisions a private
 * per-run directory; `latticed` owns the Ed25519 key and serves signatures.
 */
async function runWithNativeDaemon(opts: RunOptions): Promise<void> {
  if (opts.noInternet && !opts.useDocker) {
    throw new Error('--no-internet requires Docker until the native network sandbox is available');
  }
  const agent = loadAgent(opts.agentName);
  const runDir = fs.mkdtempSync(path.join(os.tmpdir(), 'latticed-run-'));
  fs.chmodSync(runDir, 0o700);
  const keyFile = path.join(runDir, 'agent-ed25519.pem');
  const tokenFile = path.join(runDir, 'session.token');
  const socketPath = path.join(runDir, 'daemon.sock');
  const sessionToken = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(keyFile, agent.privateKey, { mode: 0o600 });
  fs.writeFileSync(tokenFile, sessionToken, { mode: 0o600 });
  fs.chmodSync(keyFile, 0o600);
  fs.chmodSync(tokenFile, 0o600);

  let daemon: ChildProcess | undefined;
  try {
    daemon = await startNativeDaemon(keyFile, tokenFile, socketPath);
    // `latticed` has parsed the PEM; never expose the private-key material to
    // the Rust agent nor mount it into a Docker container.
    fs.unlinkSync(keyFile);
    if (opts.useDocker) {
      await runNativeInDocker(opts, runDir, socketPath, tokenFile);
    } else {
      await runNativeWithProxy(opts, socketPath, tokenFile);
    }
  } finally {
    if (daemon) await stopChild(daemon);
    fs.rmSync(runDir, { recursive: true, force: true });
  }
}

function nativeDaemonBinary(): string {
  const candidate = process.env.LATTICED_BIN?.trim() || path.resolve(process.cwd(), 'build/daemon/latticed');
  if (!fs.existsSync(candidate)) {
    throw new Error(`Native daemon not found at ${candidate}. Run: npm run build:native`);
  }
  return candidate;
}

function startNativeDaemon(keyFile: string, tokenFile: string, socketPath: string): Promise<ChildProcess> {
  const daemon = spawn(nativeDaemonBinary(), [
    '--socket', socketPath,
    '--key-file', keyFile,
    '--session-token-file', tokenFile,
  ], { stdio: ['ignore', 'inherit', 'inherit'] });
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => finish(new Error('Timed out waiting for native daemon socket')), 5_000);
    const poll = setInterval(() => {
      if (fs.existsSync(socketPath)) finish();
    }, 20);
    const finish = (error?: Error) => {
      clearTimeout(timeout);
      clearInterval(poll);
      daemon.off('error', onError);
      daemon.off('exit', onExit);
      if (error) reject(error); else resolve(daemon);
    };
    const onError = (error: Error) => finish(error);
    const onExit = (code: number | null) => finish(new Error(`Native daemon exited before ready (${code ?? 'signal'})`));
    daemon.once('error', onError);
    daemon.once('exit', onExit);
  });
}

function stopChild(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return Promise.resolve();
  return new Promise(resolve => {
    const timeout = setTimeout(() => {
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
    }, 2_000);
    child.once('exit', () => { clearTimeout(timeout); resolve(); });
    child.kill('SIGTERM');
  });
}

async function runNativeWithProxy(opts: RunOptions, socketPath: string, tokenFile: string): Promise<void> {
  const proxy = `http://127.0.0.1:${opts.proxyPort}`;
  const [cmd, ...args] = opts.command;
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    HTTP_PROXY: proxy, HTTPS_PROXY: proxy,
    http_proxy: proxy, https_proxy: proxy,
    LATTICE_AGENT: opts.agentName,
    LATTICE_DAEMON_SOCKET: socketPath,
    LATTICE_SESSION_TOKEN_FILE: tokenFile,
    LATTICE_DIR,
    NO_PROXY: '',
  };
  await spawnChild(cmd, args, env, opts.agentName);
}

async function runNativeInDocker(opts: RunOptions, runDir: string, socketPath: string, tokenFile: string): Promise<void> {
  const proxy = `http://host.docker.internal:${opts.proxyPort}`;
  const containerDir = '/run/latticed';
  const currentUid = typeof process.getuid === 'function' ? process.getuid() : undefined;
  const currentGid = typeof process.getgid === 'function' ? process.getgid() : undefined;
  const args = [
    'run', '--rm',
    ...(opts.noInternet ? ['--network', 'none'] : []),
    '-e', `HTTP_PROXY=${proxy}`,
    '-e', `HTTPS_PROXY=${proxy}`,
    '-e', `http_proxy=${proxy}`,
    '-e', `https_proxy=${proxy}`,
    '-e', `LATTICE_AGENT=${opts.agentName}`,
    '-e', `LATTICE_DAEMON_SOCKET=${containerDir}/${path.basename(socketPath)}`,
    '-e', `LATTICE_SESSION_TOKEN_FILE=${containerDir}/${path.basename(tokenFile)}`,
    ...(currentUid !== undefined && currentGid !== undefined ? ['--user', `${currentUid}:${currentGid}`] : []),
    '-v', `${runDir}:${containerDir}:ro`,
    '-v', `${process.cwd()}:/workspace`,
    '-w', '/workspace',
    detectImage(opts.command[0]),
    ...opts.command,
  ];
  console.log(`[lattice] docker ${args.join(' ')}`);
  await spawnChild('docker', args, process.env as NodeJS.ProcessEnv, opts.agentName);
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
