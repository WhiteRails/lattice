#!/usr/bin/env ts-node
/**
 * cmd/lattice.ts — The lattice CLI
 *
 * Usage: npx ts-node cmd/lattice.ts <command> [options]
 * Or via npm:  npm run lattice -- <command>
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
  tailLog, logPath, LATTICE_DIR,
} from '../node/state';
import { PolicyLoader } from '../node/policy-loader';
import { ping }         from '../node/ping';
import { runAgent }     from '../node/runner';
import { EntryNode, DEFAULT_ENTRY_PORT } from '../node/entry';
import { RelayNode, DEFAULT_RELAY_PORT } from '../node/relay';
import { ServiceGateway } from '../node/gateway';
import { createBatch, generateProof } from '../node/batch';
import {
  deployLatticeChain,
  submitCheckpoint,
  verifyCheckpointOnChain,
  chainRegisterCertType,
  chainRegisterIssuer,
  chainSetIssuerPermission,
  chainRegisterNamespace,
  chainUpdateNamespaceServiceBinding,
  chainSetNamespaceAccessPolicy,
  chainGetNamespace,
  chainGetIssuer,
  chainGetCertType,
  chainIssuerCanIssue,
  chainTransferOwnership,
  chainSetReservedOfficialSlug,
  chainGetReservedOfficialSlug,
  readPublicKeyHashFromFile,
  labelToBytes32,
  resolvePrivateKeyFromCli,
} from '../node/chain';
import { credentialMaskFromNames } from '../core/namespace-access';
import { LatticeCA }         from '../core/ca';
import { generateKeyPair } from '../core/identity';
import * as crypto from 'crypto';
import { ethers } from 'ethers';

const program = new Command();
program.name('lattice').description('Certified overlay network for autonomous AI agents').version('0.1.0');

// ── Helpers ─────────────────────────────────────────────────────────────────
function requireInit() {
  if (!isInitialized()) {
    console.error(chalk.red('Not initialized. Run: lattice init'));
    process.exit(1);
  }
}
function ok(msg: string) { console.log(`${chalk.green('✓')} ${msg}`); }
function err(msg: string) { console.error(`${chalk.red('✗')} ${msg}`); process.exit(1); }

/** Private key for chain txs: use --key-file (outside repo) instead of raw --key when possible. */
function requireChainPk(opts: { key?: string; keyFile?: string }): string {
  try {
    return resolvePrivateKeyFromCli(opts);
  } catch (e: any) {
    err(e.message);
    throw e;
  }
}

// ── init ────────────────────────────────────────────────────────────────────
program.command('init').description('Initialize Lattice (~/.lattice)').action(() => {
  if (isInitialized()) { console.log(chalk.yellow('Already initialized.')); return; }
  initDirs();
  const ca = new LatticeCA('ca.local');
  saveCA({
    caId: ca.id,
    publicKey: ca.publicKey,
    privateKey: ca.privateKey,
    overlaySecret: crypto.randomBytes(32).toString('base64'),
    createdAt: new Date().toISOString(),
  });
  ok(`Lattice initialized at ${chalk.cyan(LATTICE_DIR)}`);
  ok('Local CA created: ca.local');
  console.log(chalk.dim('\nNext steps:'));
  ['lattice agent create bot1',
   'lattice service add echo --url http://localhost:9001',
   'lattice grant bot1 lp://echo.lattice echo.ping',
   'lattice gateway start',
   'lattice run --agent bot1 -- node agent.js',
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
    const caState = loadCA();
    const ca = LatticeCA.fromKeyPair(caState.caId, {
      publicKey: caState.publicKey,
      privateKey: caState.privateKey,
    });
    const signed = ca.issueAgentCert({
      agent_id: `agent:local:${name}`, owner_org: opts.org, agent_type: opts.type,
      version: '1.0', public_key: keys.publicKey,
      allowed_capability_classes: [], forbidden_capability_classes: [], expires_in_days: 365,
    });
    saveAgent(name, {
      cert: signed.cert,
      signedCert: signed,
      publicKey: keys.publicKey,
      privateKey: keys.privateKey,
      createdAt: new Date().toISOString(),
    });
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
  if (!agents.length) { console.log(chalk.dim('No agents. Run: lattice agent create <name>')); return; }
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

svc.command('add <name>').description('Register a lp://<name>.lattice service')
  .requiredOption('--url <url>', 'Backend URL')
  .option('--policy <profile>', 'Policy profile', 'default')
  .action((name, opts) => {
    requireInit();
    saveService(name, { name, address: `lp://${name}.lattice`, url: opts.url, policy_profile: opts.policy, registeredAt: new Date().toISOString() });
    ok(`Service '${chalk.cyan(`lp://${name}.lattice`)}' → ${opts.url}`);
  });

svc.command('list').description('List registered services').action(() => {
  requireInit();
  const services = listServices();
  if (!services.length) { console.log(chalk.dim('No services. Run: lattice service add <name> --url <url>')); return; }
  console.log(chalk.bold('Services:'));
  for (const n of services) {
    const s = loadService(n);
    console.log(`  ${chalk.cyan(s.address)}  →  ${chalk.dim(s.url)}`);
  }
});

// ── resolve ──────────────────────────────────────────────────────────────────
program.command('resolve <address>').description('Resolve a lp:// address').action((address) => {
  requireInit();
  const name = address.replace('lp://', '').replace('.lattice', '');
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
const nodeCmd = program.command('node').description('Manage Lattice Overlay Nodes');

nodeCmd.command('start').description('Start a Lattice Overlay Node')
  .requiredOption('--role <role>', 'Role of the node: entry, relay, or gateway')
  .option('--port <port>', 'Port to listen on')
  .option('--service <wp_url>', 'For gateway: The Lattice service address (e.g. lp://echo.lattice)')
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
program.command('run').description('Run an agent command inside Lattice sandbox')
  .requiredOption('--agent <name>', 'Agent name')
  // Default true: allow internet unless user passes --no-internet (Commander stores as `internet`).
  .option('--no-internet', 'Block normal internet (requires Docker for real isolation)', true)
  .option('--docker', 'Run inside Docker container', false)
  .option('--port <port>', 'Proxy port', String(DEFAULT_ENTRY_PORT))
  .argument('<command...>', 'Command to run')
  .action(async (command, opts) => {
    requireInit();
    try {
      await runAgent({
        agentName: opts.agent,
        noInternet: opts.internet === false,
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
program.command('ping <address>').description('Trust-ping a lp:// address')
  .option('--agent <name>', 'Check policy for agent')
  .action(async (address, opts) => {
    requireInit();
    if (!address.startsWith('lp://')) address = `lp://${address}`;
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
const chain = program.command('chain').description('LatticeChain Trust Anchor operations');

chain.command('deploy').description('Deploy LatticeChain contract to network')
  .requiredOption('--rpc <url>', 'RPC URL')
  .option('--key <key>', 'Deployer private key (hex)')
  .option('--key-file <path>', 'Deployer private key file (recommended; keep outside repo)')
  .action(async (opts) => {
    requireInit();
    const pk = requireChainPk(opts);
    console.log(chalk.dim('Deploying LatticeChain contract...'));
    try {
      const address = await deployLatticeChain(opts.rpc, pk);
      ok(`Contract deployed to: ${chalk.green(address)}`);
    } catch (e: any) { err(e.message); }
  });

const chainOwnership = chain.command('ownership').description('Contract owner (governance)');

chainOwnership
  .command('transfer <newOwnerAddress>')
  .description('Transfer LatticeChain owner (only current owner)')
  .requiredOption('--rpc <url>', 'RPC URL')
  .requiredOption('--contract <address>', 'LatticeChain address')
  .option('--key <key>', 'Current owner private key (hex)')
  .option('--key-file <path>', 'Current owner private key file')
  .action(async (newOwnerAddress, opts) => {
    requireInit();
    const pk = requireChainPk(opts);
    try {
      const txHash = await chainTransferOwnership(opts.rpc, pk, opts.contract, newOwnerAddress.trim());
      ok(`Ownership transferred  tx=${chalk.green(txHash)}`);
    } catch (e: any) { err(e.message); }
  });

const chainReserved = chain.command('reserved').description('Official lattice slug reservations (owner-only writes)');

chainReserved
  .command('set <slug>')
  .description('Mark slug (label before .lattice) as official/reserved or clear it')
  .requiredOption('--rpc <url>', 'RPC URL')
  .requiredOption('--contract <address>', 'LatticeChain address')
  .option('--key <key>', 'Owner private key (hex)')
  .option('--key-file <path>', 'Owner private key file')
  .option('--remove', 'Clear reservation (non-owner may register that slug.lattice)', false)
  .action(async (slug, opts) => {
    requireInit();
    const pk = requireChainPk(opts);
    const reserved = !opts.remove;
    try {
      const txHash = await chainSetReservedOfficialSlug(opts.rpc, pk, opts.contract, slug, reserved);
      ok(`Reserved slug updated  tx=${chalk.green(txHash)}  reserved=${reserved}`);
    } catch (e: any) { err(e.message); }
  });

chainReserved
  .command('show <slug>')
  .description('Query whether a slug is reserved for owner-only registration')
  .requiredOption('--rpc <url>', 'RPC URL')
  .requiredOption('--contract <address>', 'LatticeChain address')
  .action(async (slug, opts) => {
    try {
      const v = await chainGetReservedOfficialSlug(opts.rpc, opts.contract, slug);
      console.log(JSON.stringify({ slug, reservedOfficial: v }, null, 2));
    } catch (e: any) { err(e.message); }
  });

const chainCertType = chain
  .command('cert-type')
  .description('CertType registry (register requires contract owner)');

chainCertType
  .command('register <name>')
  .description('Register a cert type; bytes32 id is keccak256(name) unless name is 0x + 64 hex')
  .requiredOption('--rpc <url>', 'RPC URL')
  .requiredOption('--contract <address>', 'LatticeChain address')
  .option('--key <key>', 'Contract owner private key (hex)')
  .option('--key-file <path>', 'Contract owner private key file')
  .requiredOption('--level <n>', 'Assurance level (0–255)')
  .action(async (name, opts) => {
    requireInit();
    const pk = requireChainPk(opts);
    try {
      const level = parseInt(String(opts.level), 10);
      if (!Number.isFinite(level) || level < 0 || level > 255) err('--level must be 0–255');
      const { txHash, certTypeId } = await chainRegisterCertType(opts.rpc, pk, opts.contract, name, level);
      ok(`CertType registered  tx=${chalk.green(txHash)}`);
      console.log(chalk.dim(`  certTypeId: ${certTypeId}`));
    } catch (e: any) { err(e.message); }
  });

chainCertType
  .command('show <name>')
  .description('Read on-chain cert type row')
  .requiredOption('--rpc <url>', 'RPC URL')
  .requiredOption('--contract <address>', 'LatticeChain address')
  .action(async (name, opts) => {
    try {
      const r = await chainGetCertType(opts.rpc, opts.contract, name);
      console.log(JSON.stringify(r, null, 2));
    } catch (e: any) { err(e.message); }
  });

const chainIssuer = chain
  .command('issuer')
  .description('Issuer registry (register + permit require contract owner)');

chainIssuer
  .command('register <label>')
  .description('Register issuer; id = keccak256(label) unless label is 0x + 64 hex')
  .requiredOption('--rpc <url>', 'RPC URL')
  .requiredOption('--contract <address>', 'LatticeChain address')
  .option('--key <key>', 'Contract owner private key (hex)')
  .option('--key-file <path>', 'Contract owner private key file')
  .requiredOption('--type <label>', 'Issuer type label (hashed to bytes32)')
  .option('--pub-key-hash <hex>', 'bytes32 public key hash (0x + 64 hex)')
  .option('--pub-key-file <path>', 'UTF-8 file; hash = keccak256(contents) → bytes32')
  .action(async (label, opts) => {
    requireInit();
    const pk = requireChainPk(opts);
    if (!opts.pubKeyHash && !opts.pubKeyFile) err('Provide --pub-key-hash or --pub-key-file');
    let publicKeyHash: string;
    if (opts.pubKeyHash) {
      const h = (opts.pubKeyHash as string).trim();
      if (!/^0x[0-9a-fA-F]{64}$/.test(h)) err('--pub-key-hash must be 0x + 64 hex characters');
      publicKeyHash = h;
    } else {
      const fp = path.resolve(process.cwd(), opts.pubKeyFile as string);
      if (!fs.existsSync(fp)) err(`File not found: ${fp}`);
      publicKeyHash = readPublicKeyHashFromFile(fp);
    }
    try {
      const { txHash, issuerId } = await chainRegisterIssuer(
        opts.rpc,
        pk,
        opts.contract,
        label,
        opts.type as string,
        publicKeyHash,
      );
      ok(`Issuer registered  tx=${chalk.green(txHash)}`);
      console.log(chalk.dim(`  issuerId: ${issuerId}`));
    } catch (e: any) { err(e.message); }
  });

chainIssuer
  .command('permit <issuerLabel> <certTypeName>')
  .description('Allow or deny an issuer to issue a cert type')
  .requiredOption('--rpc <url>', 'RPC URL')
  .requiredOption('--contract <address>', 'LatticeChain address')
  .option('--key <key>', 'Contract owner private key (hex)')
  .option('--key-file <path>', 'Contract owner private key file')
  .option('--deny', 'Set permission to false', false)
  .action(async (issuerLabel, certTypeName, opts) => {
    requireInit();
    const pk = requireChainPk(opts);
    try {
      const allowed = !opts.deny;
      const txHash = await chainSetIssuerPermission(
        opts.rpc,
        pk,
        opts.contract,
        issuerLabel,
        certTypeName,
        allowed,
      );
      ok(`Issuer permission updated  tx=${chalk.green(txHash)}  allowed=${allowed}`);
    } catch (e: any) { err(e.message); }
  });

chainIssuer
  .command('show <label>')
  .description('Read on-chain issuer row')
  .requiredOption('--rpc <url>', 'RPC URL')
  .requiredOption('--contract <address>', 'LatticeChain address')
  .action(async (label, opts) => {
    try {
      const r = await chainGetIssuer(opts.rpc, opts.contract, label);
      console.log(JSON.stringify(r, null, 2));
      console.log(chalk.dim(`  issuerId (bytes32): ${r.issuerId}`));
    } catch (e: any) { err(e.message); }
  });

chainIssuer
  .command('can-issue <issuerLabel> <certTypeName>')
  .description('Query canIssue(issuerId, certTypeId)')
  .requiredOption('--rpc <url>', 'RPC URL')
  .requiredOption('--contract <address>', 'LatticeChain address')
  .action(async (issuerLabel, certTypeName, opts) => {
    try {
      const v = await chainIssuerCanIssue(opts.rpc, opts.contract, issuerLabel, certTypeName);
      console.log(JSON.stringify({ issuerLabel, certTypeName, canIssue: v }, null, 2));
    } catch (e: any) { err(e.message); }
  });

const chainNs = chain
  .command('namespace')
  .description('NamespaceRegistry: only `label.lattice` (ASCII lowercase [a-z0-9-]+). Official slugs (governments, lattice, …) → contract owner only.');

chainNs
  .command('register <fqdn>')
  .description('Register namespace on-chain (FQDN must end with .lattice; reserved slugs require owner key)')
  .requiredOption('--rpc <url>', 'RPC URL')
  .requiredOption('--contract <address>', 'LatticeChain address')
  .option('--key <key>', 'Caller private key (hex)')
  .option('--key-file <path>', 'Caller private key file')
  .requiredOption('--owner-issuer <label>', 'Issuer label (hashed to bytes32) as namespace owner')
  .option('--service-cert-hash <hex>', 'bytes32 service cert hash (default 0x0…0)')
  .option('--metadata-hash <hex>', 'bytes32 metadata hash (default 0x0…0)')
  .option('--namespace-admin <address>', 'Domain admin (default: caller); may update service binding + access policy')
  .option('--public', 'Accept any client at gateway (see docs/Namespace-firewall-gateway.md)')
  .option('--credentials <csv>', 'When not --public: OR mask from gov,enterprise,model (comma-separated)')
  .option('--min-assurance <n>', 'Minimum cert assurance level when not public (default 0)', '0')
  .action(async (fqdn, opts) => {
    requireInit();
    const pk = requireChainPk(opts);
    try {
      const publicAccess = Boolean(opts.public);
      const credCsv = (opts.credentials as string | undefined)?.trim();
      if (publicAccess && credCsv) err('Use either --public or --credentials, not both');
      let credentialMask = 0;
      if (!publicAccess && credCsv) {
        credentialMask = credentialMaskFromNames(credCsv.split(',').map(s => s.trim()).filter(Boolean));
      }
      const minAssuranceLevel = Math.max(0, Math.min(255, parseInt(String(opts.minAssurance), 10) || 0));
      const { txHash, nameHash, ownerIssuerId } = await chainRegisterNamespace(
        opts.rpc,
        pk,
        opts.contract,
        fqdn,
        opts.ownerIssuer as string,
        opts.serviceCertHash as string | undefined,
        opts.metadataHash as string | undefined,
        opts.namespaceAdmin as string | undefined,
        publicAccess,
        credentialMask,
        minAssuranceLevel,
      );
      ok(`Namespace registered  tx=${chalk.green(txHash)}`);
      console.log(chalk.dim(`  nameHash:       ${nameHash}`));
      console.log(chalk.dim(`  ownerIssuerId:  ${ownerIssuerId}`));
    } catch (e: any) { err(e.message); }
  });

chainNs
  .command('update-service <fqdn>')
  .description('Update serviceCertHash / metadataHash (namespace admin or contract owner)')
  .requiredOption('--rpc <url>', 'RPC URL')
  .requiredOption('--contract <address>', 'LatticeChain address')
  .option('--key <key>', 'Private key (hex)')
  .option('--key-file <path>', 'Private key file')
  .option('--service-cert-hash <hex>', 'bytes32 (omit or 0 to keep unchanged)')
  .option('--metadata-hash <hex>', 'bytes32 (omit or 0 to keep unchanged)')
  .action(async (fqdn, opts) => {
    requireInit();
    const pk = requireChainPk(opts);
    try {
      const txHash = await chainUpdateNamespaceServiceBinding(
        opts.rpc,
        pk,
        opts.contract,
        fqdn,
        opts.serviceCertHash as string | undefined,
        opts.metadataHash as string | undefined,
      );
      ok(`Namespace service binding updated  tx=${chalk.green(txHash)}`);
    } catch (e: any) { err(e.message); }
  });

chainNs
  .command('set-policy <fqdn>')
  .description('Set publicAccess, credentialMask, minAssuranceLevel (namespace admin or contract owner)')
  .requiredOption('--rpc <url>', 'RPC URL')
  .requiredOption('--contract <address>', 'LatticeChain address')
  .option('--key <key>', 'Private key (hex)')
  .option('--key-file <path>', 'Private key file')
  .option('--public', 'Open namespace at gateway policy layer')
  .option('--credentials <csv>', 'When not --public: gov,enterprise,model (comma OR)')
  .option('--min-assurance <n>', 'Minimum assurance when not public', '0')
  .action(async (fqdn, opts) => {
    requireInit();
    const pk = requireChainPk(opts);
    try {
      const publicAccess = Boolean(opts.public);
      const credCsv = (opts.credentials as string | undefined)?.trim();
      if (publicAccess && credCsv) err('Use either --public or --credentials, not both');
      let credentialMask = 0;
      if (!publicAccess && credCsv) {
        credentialMask = credentialMaskFromNames(credCsv.split(',').map(s => s.trim()).filter(Boolean));
      }
      const minAssuranceLevel = Math.max(0, Math.min(255, parseInt(String(opts.minAssurance), 10) || 0));
      const txHash = await chainSetNamespaceAccessPolicy(
        opts.rpc,
        pk,
        opts.contract,
        fqdn,
        publicAccess,
        credentialMask,
        minAssuranceLevel,
      );
      ok(`Namespace policy updated  tx=${chalk.green(txHash)}`);
    } catch (e: any) { err(e.message); }
  });

chainNs
  .command('show <fqdn>')
  .description('Read NamespaceRecord (nameHash = keccak256(utf8(fqdn)) for valid lattice FQDNs)')
  .requiredOption('--rpc <url>', 'RPC URL')
  .requiredOption('--contract <address>', 'LatticeChain address')
  .action(async (fqdn, opts) => {
    try {
      const r = await chainGetNamespace(opts.rpc, opts.contract, fqdn);
      console.log(JSON.stringify(r, null, 2));
      console.log(chalk.dim(`  nameHash (bytes32): ${r.nameHash}`));
    } catch (e: any) { err(e.message); }
  });

chainNs
  .command('hash <fqdn>')
  .description('Print nameHash (keccak256 of UTF-8 fqdn) as stored on-chain')
  .action(fqdn => {
    console.log(labelToBytes32(fqdn.trim()));
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

program.command('checkpoint submit').description('Submit a batch Merkle root to the LatticeChain (contract owner only)')
  .requiredOption('--batch <id>', 'Batch ID')
  .requiredOption('--rpc <url>', 'RPC URL')
  .requiredOption('--contract <address>', 'LatticeChain contract address')
  .option('--key <key>', 'Owner private key (hex)')
  .option('--key-file <path>', 'Owner private key file')
  .action(async (opts) => {
    requireInit();
    const pk = requireChainPk(opts);
    const f = path.join(LATTICE_DIR, 'batches', `${opts.batch}.json`);
    if (!fs.existsSync(f)) err(`Batch '${opts.batch}' not found`);
    const meta = JSON.parse(fs.readFileSync(f, 'utf-8'));
    console.log(chalk.dim(`Submitting checkpoint for ${opts.batch}...`));
    try {
      const txHash = await submitCheckpoint(meta, opts.rpc, pk, opts.contract);
      ok(`Checkpoint anchored at tx: ${chalk.green(txHash)}`);
    } catch (e: any) { err(e.message); }
  });

program.command('proof <action_id>').description('Generate and verify Merkle proof for an action')
  .option('--rpc <url>', 'RPC URL to verify on-chain checkpoint (optional)')
  .option('--contract <address>', 'LatticeChain contract address (optional)')
  .action(async (actionId, opts) => {
    requireInit();
    try {
      const { batch, proof } = generateProof(actionId);
      console.log(chalk.bold(`\n  Action: ${chalk.cyan(actionId)}`));
      console.log(`  Included in batch: ${chalk.yellow(batch.batch_id)}`);
      console.log(`  Merkle root:       ${chalk.green(batch.merkle_root)}`);
      
      let onChainVerified = false;
      if (opts.rpc && opts.contract) {
        console.log(chalk.dim('  Querying LatticeChain...'));
        const result = await verifyCheckpointOnChain(batch.batch_id, opts.rpc, opts.contract);
        if (result.anchored && result.merkleRoot !== undefined) {
          const chainRoot = ethers.hexlify(result.merkleRoot);
          const raw = batch.merkle_root.replace(/^0x/i, '');
          const batchRoot = ethers.hexlify('0x' + raw);
          if (chainRoot === batchRoot) {
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
