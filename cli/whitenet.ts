#!/usr/bin/env ts-node
/**
 * cmd/whitenet.ts — The whitenet CLI
 *
 * Usage: npx ts-node cmd/whitenet.ts <command> [options]
 * Or via npm:  npm run whitenet -- <command>
 */
import { Command } from 'commander';
import chalk from 'chalk';
import * as fs from 'fs';
import * as path from 'path';
import {
  initDirs, isInitialized, saveCA, loadCA,
  saveAgent, loadAgent, agentExists, listAgents,
  saveService, loadService, serviceExists, listServices,
  saveRevocation, isRevoked, listRevocations,
  tailLog, logPath, WHITENET_DIR,
} from '../node/state';
import { PolicyLoader } from '../node/policy-loader';
import { ping }         from '../node/ping';
import { runAgent }     from '../node/runner';
import { EntryNode, DEFAULT_ENTRY_PORT } from '../node/entry';
import { RelayNode, DEFAULT_RELAY_PORT } from '../node/relay';
import { ServiceGateway } from '../node/gateway';
import { createBatch, generateProof } from '../node/batch';
import { deployWhiteChain, submitCheckpoint, verifyCheckpointOnChain } from '../node/chain';
import { WhiteCA }         from '../core/ca';
import { generateKeyPair } from '../core/identity';

const program = new Command();
program.name('whitenet').description('Certified overlay network for autonomous AI agents').version('0.1.0');

// ── Helpers ─────────────────────────────────────────────────────────────────
function requireInit() {
  if (!isInitialized()) {
    console.error(chalk.red('Not initialized. Run: whitenet init'));
    process.exit(1);
  }
}
function ok(msg: string) { console.log(`${chalk.green('✓')} ${msg}`); }
function err(msg: string) { console.error(`${chalk.red('✗')} ${msg}`); process.exit(1); }

// ── init ────────────────────────────────────────────────────────────────────
program.command('init').description('Initialize WhiteNet (~/.whitenet)').action(() => {
  if (isInitialized()) { console.log(chalk.yellow('Already initialized.')); return; }
  initDirs();
  const ca = new WhiteCA('ca.local');
  saveCA({ caId: ca.id, publicKey: ca.publicKey, createdAt: new Date().toISOString() });
  ok(`WhiteNet initialized at ${chalk.cyan(WHITENET_DIR)}`);
  ok('Local CA created: ca.local');
  console.log(chalk.dim('\nNext steps:'));
  ['whitenet agent create bot1',
   'whitenet service add echo --url http://localhost:9001',
   'whitenet grant bot1 wp://echo.white echo.ping',
   'whitenet gateway start',
   'whitenet run --agent bot1 -- node agent.js',
  ].forEach(s => console.log('  ' + chalk.dim(s)));
});

// ── agent ───────────────────────────────────────────────────────────────────
const agent = program.command('agent').description('Manage agents');

agent.command('create <name>').description('Create an agent with a certificate')
  .option('--type <type>', 'Agent type', 'autonomous')
  .option('--org <org>', 'Owner org', 'local')
  .action((name, opts) => {
    requireInit();
    if (agentExists(name)) err(`Agent '${name}' already exists`);
    const keys = generateKeyPair();
    const ca = new WhiteCA('ca.local');
    const signed = ca.issueAgentCert({
      agent_id: `agent:local:${name}`, owner_org: opts.org, agent_type: opts.type,
      version: '1.0', public_key: keys.publicKey,
      allowed_capability_classes: [], forbidden_capability_classes: [], expires_in_days: 365,
    });
    saveAgent(name, { cert: signed.cert, publicKey: keys.publicKey, createdAt: new Date().toISOString() });
    new PolicyLoader().deny(name, 'internet:*');
    ok(`Agent '${chalk.cyan(name)}' created`);
    console.log(chalk.dim(`  cert: ${signed.cert.id}`));
    console.log(chalk.dim('  default policy: deny internet:*'));
  });

agent.command('revoke <name>').description('Revoke an agent').action((name) => {
  requireInit();
  if (!agentExists(name)) err(`Agent '${name}' not found`);
  saveRevocation(name);
  ok(`Agent '${chalk.red(name)}' revoked — future requests blocked`);
});

agent.command('list').description('List agents').action(() => {
  requireInit();
  const agents = listAgents();
  if (!agents.length) { console.log(chalk.dim('No agents. Run: whitenet agent create <name>')); return; }
  const revoked = listRevocations();
  console.log(chalk.bold('Agents:'));
  for (const n of agents) {
    const status = revoked.includes(n) ? chalk.red('revoked') : chalk.green('active');
    console.log(`  ${chalk.cyan(n)}  [${status}]`);
  }
});

// ── cert ────────────────────────────────────────────────────────────────────
program.command('cert inspect <name>').description('Show agent certificate').action((name) => {
  requireInit();
  const a = loadAgent(name);
  const c = a.cert;
  console.log(chalk.bold('Certificate:'));
  [['id', c.id], ['agent_id', c.agent_id], ['type', c.type], ['issuer', c.issuer],
   ['issued_at', c.issued_at], ['expires_at', c.expires_at ?? 'never'],
   ['revoked', isRevoked(name) ? chalk.red('YES') : chalk.green('NO')],
  ].forEach(([k, v]) => console.log(`  ${chalk.dim(String(k) + ':')}  ${v}`));
});

// ── service ──────────────────────────────────────────────────────────────────
const svc = program.command('service').description('Manage services');

svc.command('add <name>').description('Register a wp://<name>.white service')
  .requiredOption('--url <url>', 'Backend URL')
  .option('--policy <profile>', 'Policy profile', 'default')
  .action((name, opts) => {
    requireInit();
    saveService(name, { name, address: `wp://${name}.white`, url: opts.url, policy_profile: opts.policy, registeredAt: new Date().toISOString() });
    ok(`Service '${chalk.cyan(`wp://${name}.white`)}' → ${opts.url}`);
  });

svc.command('list').description('List registered services').action(() => {
  requireInit();
  const services = listServices();
  if (!services.length) { console.log(chalk.dim('No services. Run: whitenet service add <name> --url <url>')); return; }
  console.log(chalk.bold('Services:'));
  for (const n of services) {
    const s = loadService(n);
    console.log(`  ${chalk.cyan(s.address)}  →  ${chalk.dim(s.url)}`);
  }
});

// ── resolve ──────────────────────────────────────────────────────────────────
program.command('resolve <address>').description('Resolve a wp:// address').action((address) => {
  requireInit();
  const name = address.replace('wp://', '').replace('.white', '');
  if (!serviceExists(name)) err(`Service '${address}' not found`);
  const s = loadService(name);
  console.log(chalk.bold(`Resolved: ${address}`));
  Object.entries(s).forEach(([k, v]) => console.log(`  ${chalk.dim(k + ':')}  ${v}`));
});

// ── grant / deny ─────────────────────────────────────────────────────────────
program.command('grant <agent> <resource> <actions...>').description('Grant capability to agent')
  .action((agentName, resource, actions) => {
    requireInit();
    if (!agentExists(agentName)) err(`Agent '${agentName}' not found`);
    new PolicyLoader().grant(agentName, resource, actions);
    ok(`${chalk.cyan(agentName)} can now ${chalk.green(actions.join(', '))} on ${chalk.cyan(resource)}`);
  });

program.command('deny <agent> <resource>').description('Deny resource access for agent')
  .action((agentName, resource) => {
    requireInit();
    if (!agentExists(agentName)) err(`Agent '${agentName}' not found`);
    new PolicyLoader().deny(agentName, resource);
    ok(`${chalk.cyan(agentName)} denied access to ${chalk.red(resource)}`);
  });

// ── policy ───────────────────────────────────────────────────────────────────
const pol = program.command('policy').description('Manage policies');

pol.command('inspect <agent>').description('Show agent policy').action((agentName) => {
  requireInit();
  if (!agentExists(agentName)) err(`Agent '${agentName}' not found`);
  console.log(new PolicyLoader().inspect(agentName));
});

// ── gateway ──────────────────────────────────────────────────────────────────
const nodeCmd = program.command('node').description('Manage WhiteNet Overlay Nodes');

nodeCmd.command('start').description('Start a WhiteNet Overlay Node')
  .requiredOption('--role <role>', 'Role of the node: entry, relay, or gateway')
  .option('--port <port>', 'Port to listen on')
  .option('--service <wp_url>', 'For gateway: The WhiteNet service address (e.g. wp://echo.white)')
  .option('--target <http_url>', 'For gateway: The internal HTTP backend to proxy to')
  .action((opts) => {
    requireInit();
    const port = opts.port ? parseInt(opts.port, 10) : undefined;
    
    if (opts.role === 'entry') {
      new EntryNode(port || DEFAULT_ENTRY_PORT);
    } else if (opts.role === 'relay') {
      new RelayNode(port || DEFAULT_RELAY_PORT);
    } else if (opts.role === 'gateway') {
      if (!opts.service || !opts.target) err('Gateway role requires --service and --target');
      new ServiceGateway(opts.service, opts.target, port || 8889);
    } else {
      err(`Unknown role: ${opts.role}`);
    }
  });

// ── run ───────────────────────────────────────────────────────────────────────
program.command('run').description('Run an agent command inside WhiteNet sandbox')
  .requiredOption('--agent <name>', 'Agent name')
  .option('--no-internet', 'Block normal internet (requires Docker for real isolation)', false)
  .option('--docker', 'Run inside Docker container', false)
  .option('--port <port>', 'Proxy port', String(DEFAULT_ENTRY_PORT))
  .argument('<command...>', 'Command to run')
  .action(async (command, opts) => {
    requireInit();
    try {
      await runAgent({
        agentName: opts.agent,
        noInternet: opts.noInternet,
        useDocker: opts.docker,
        proxyPort: parseInt(opts.port),
        command,
      });
    } catch (e: any) { err(e.message); }
  });

// ── logs ─────────────────────────────────────────────────────────────────────
const logs = program.command('logs').description('View action logs');

logs.command('tail').description('Tail the action log')
  .option('--n <count>', 'Number of entries', '20')
  .option('--follow', 'Follow log (watch for new entries)', false)
  .action((opts) => {
    requireInit();
    const entries = tailLog(parseInt(opts.n));
    if (!entries.length) { console.log(chalk.dim('No log entries yet.')); return; }

    printLogEntries(entries);

    if (opts.follow) {
      const f = logPath();
      let size = fs.statSync(f).size;
      setInterval(() => {
        const newSize = fs.statSync(f).size;
        if (newSize <= size) return;
        const chunk = fs.readFileSync(f).slice(size).toString();
        size = newSize;
        chunk.trim().split('\n').filter(Boolean).forEach(l => {
          try { printLogEntry(JSON.parse(l)); } catch {}
        });
      }, 500);
    }
  });

// ── ping ─────────────────────────────────────────────────────────────────────
program.command('ping <address>').description('Trust-ping a wp:// address')
  .option('--agent <name>', 'Check policy for agent')
  .action(async (address, opts) => {
    requireInit();
    if (!address.startsWith('wp://')) address = `wp://${address}`;
    const result = await ping(address, opts.agent);

    console.log(chalk.bold(`\n  ${address}`));
    console.log(`  resolved:    ${result.resolved ? chalk.green('yes') : chalk.red('no')}`);
    console.log(`  cert:        ${result.cert_status === 'valid' ? chalk.green('valid') : chalk.red(result.cert_status)}`);
    console.log(`  revocation:  ${result.revocation === 'fresh' ? chalk.green('fresh') : chalk.yellow(result.revocation)}`);
    console.log(`  reachable:   ${result.reachable ? chalk.green('yes') : chalk.red('no (service offline)')}`);
    console.log(`  latency:     ${result.latency_ms}ms`);

    if (opts.agent) {
      console.log(`  agent:       ${chalk.cyan(opts.agent)}`);
      if (result.actions_allowed.length) {
        console.log(chalk.dim('\n  actions allowed:'));
        result.actions_allowed.forEach(a => console.log(`    ${chalk.green('✓')} ${a}`));
      }
      if (result.actions_blocked.length) {
        console.log(chalk.dim('\n  actions blocked:'));
        result.actions_blocked.forEach(a => console.log(`    ${chalk.red('✗')} ${a}`));
      }
    }
    console.log();
  });

// ── Helpers ───────────────────────────────────────────────────────────────────
function printLogEntries(entries: object[]) { entries.forEach(printLogEntry); }
function printLogEntry(e: any) {
  const d = chalk.dim(e.timestamp?.slice(0, 19) ?? '');
  const icon = e.decision === 'allow' ? chalk.green('✓')
    : e.decision === 'require_human_approval' ? chalk.yellow('⚠')
    : chalk.red('✗');
  console.log(`${d}  ${icon}  ${chalk.cyan(e.agent ?? '?')}  ${e.action ?? ''}  ${chalk.dim(e.resource ?? '')}  ${chalk.dim(e.reason ?? '')}`);
}

// ── chain / batch / proof ───────────────────────────────────────────────────
const chain = program.command('chain').description('WhiteChain Trust Anchor operations');

chain.command('deploy').description('Deploy WhiteChain contract to network')
  .requiredOption('--rpc <url>', 'RPC URL')
  .requiredOption('--key <key>', 'Private key')
  .action(async (opts) => {
    requireInit();
    console.log(chalk.dim('Deploying WhiteChain contract...'));
    try {
      const address = await deployWhiteChain(opts.rpc, opts.key);
      ok(`Contract deployed to: ${chalk.green(address)}`);
    } catch (e: any) { err(e.message); }
  });

logs.command('batch').description('Create a Merkle batch of unbatched action logs')
  .action(() => {
    requireInit();
    try {
      const meta = createBatch();
      ok(`Created ${chalk.cyan(meta.batch_id)} with ${chalk.yellow(meta.action_count)} actions.`);
      console.log(chalk.dim(`  Merkle root: ${meta.merkle_root}`));
    } catch (e: any) { err(e.message); }
  });

program.command('checkpoint submit').description('Submit a batch Merkle root to the WhiteChain')
  .requiredOption('--batch <id>', 'Batch ID')
  .requiredOption('--rpc <url>', 'RPC URL')
  .requiredOption('--key <key>', 'Private key')
  .requiredOption('--contract <address>', 'WhiteChain contract address')
  .action(async (opts) => {
    requireInit();
    const f = path.join(WHITENET_DIR, 'batches', `${opts.batch}.json`);
    if (!fs.existsSync(f)) err(`Batch '${opts.batch}' not found`);
    const meta = JSON.parse(fs.readFileSync(f, 'utf-8'));
    console.log(chalk.dim(`Submitting checkpoint for ${opts.batch}...`));
    try {
      const txHash = await submitCheckpoint(meta, opts.rpc, opts.key, opts.contract);
      ok(`Checkpoint anchored at tx: ${chalk.green(txHash)}`);
    } catch (e: any) { err(e.message); }
  });

program.command('proof <action_id>').description('Generate and verify Merkle proof for an action')
  .option('--rpc <url>', 'RPC URL to verify on-chain checkpoint (optional)')
  .option('--contract <address>', 'WhiteChain contract address (optional)')
  .action(async (actionId, opts) => {
    requireInit();
    try {
      const { batch, proof } = generateProof(actionId);
      console.log(chalk.bold(`\n  Action: ${chalk.cyan(actionId)}`));
      console.log(`  Included in batch: ${chalk.yellow(batch.batch_id)}`);
      console.log(`  Merkle root:       ${chalk.green(batch.merkle_root)}`);
      
      let onChainVerified = false;
      if (opts.rpc && opts.contract) {
        console.log(chalk.dim('  Querying WhiteChain...'));
        const result = await verifyCheckpointOnChain(batch.batch_id, opts.rpc, opts.contract);
        if (result.anchored) {
          if (result.merkleRoot === batch.merkle_root) {
            onChainVerified = true;
            console.log(`  Checkpoint:        ${chalk.green('on-chain (verified)')}`);
            console.log(`  Signer:            ${chalk.dim(result.signer)}`);
          } else {
            console.log(`  Checkpoint:        ${chalk.red('MISMATCH')} (on-chain root: ${result.merkleRoot})`);
          }
        } else {
          console.log(`  Checkpoint:        ${chalk.red('Not found on-chain')}`);
        }
      } else {
        console.log(`  Checkpoint:        ${chalk.dim('Skipped on-chain verify (missing --rpc/--contract)')}`);
      }
      console.log();
    } catch (e: any) { err(e.message); }
  });

program.parse(process.argv);
