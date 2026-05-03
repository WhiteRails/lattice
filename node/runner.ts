import { spawn } from 'child_process';
import * as path from 'path';
import { agentExists, isRevoked, WHITENET_DIR } from './state';

export interface RunOptions {
  agentName: string;
  noInternet: boolean;
  proxyPort: number;
  command: string[];
  useDocker: boolean;
}

export async function runAgent(opts: RunOptions): Promise<void> {
  if (!agentExists(opts.agentName))
    throw new Error(`Agent '${opts.agentName}' not found. Run: whitenet agent create ${opts.agentName}`);
  if (isRevoked(opts.agentName))
    throw new Error(`Agent '${opts.agentName}' is revoked`);

  return opts.useDocker ? runInDocker(opts) : runWithProxy(opts);
}

async function runWithProxy(opts: RunOptions): Promise<void> {
  const proxy = `http://127.0.0.1:${opts.proxyPort}`;
  if (opts.noInternet)
    console.warn('[whitenet] --no-internet without Docker only injects proxy env vars. Use --docker for real isolation.');

  const env: NodeJS.ProcessEnv = {
    ...process.env,
    HTTP_PROXY: proxy, HTTPS_PROXY: proxy,
    http_proxy: proxy, https_proxy: proxy,
    WHITENET_AGENT: opts.agentName,
    WHITENET_DIR,
    NO_PROXY: '',
  };

  const [cmd, ...args] = opts.command;
  return spawnChild(cmd, args, env);
}

async function runInDocker(opts: RunOptions): Promise<void> {
  const proxy = `http://host.docker.internal:${opts.proxyPort}`;
  const args = [
    'run', '--rm',
    ...(opts.noInternet ? ['--network', 'none'] : []),
    '-e', `HTTP_PROXY=${proxy}`,
    '-e', `HTTPS_PROXY=${proxy}`,
    '-e', `http_proxy=${proxy}`,
    '-e', `https_proxy=${proxy}`,
    '-e', `WHITENET_AGENT=${opts.agentName}`,
    '-v', `${process.cwd()}:/workspace`,
    '-w', '/workspace',
    detectImage(opts.command[0]),
    ...opts.command,
  ];
  console.log(`[whitenet] docker ${args.join(' ')}`);
  return spawnChild('docker', args, process.env as NodeJS.ProcessEnv);
}

function spawnChild(cmd: string, args: string[], env: NodeJS.ProcessEnv): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(cmd, args, { env, stdio: 'inherit' });
    child.on('exit', code => code === 0 ? resolve() : reject(new Error(`Exited with code ${code}`)));
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
