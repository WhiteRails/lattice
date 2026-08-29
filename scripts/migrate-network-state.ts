import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import * as yaml from 'js-yaml';

interface LegacyPolicyRule { resource: string; actions?: string[] }
interface LegacyPolicy {
  agent: string;
  network?: { default?: 'allow' | 'deny' };
  allow?: LegacyPolicyRule[];
  deny?: LegacyPolicyRule[];
}

interface Arguments {
  latticeHome: string;
  agent: string;
  organization: string;
  gateway: string;
  gatewayName: string;
  gatewayPin: string;
  serviceTlsPin: string;
  token: string;
  mode: 'split' | 'full';
  out: string;
  terminateTls: boolean;
  egressCidrs: string[];
}

function fail(message: string): never {
  throw new Error(message);
}

function parseArguments(argv: string[]): Arguments {
  const values = new Map<string, string>();
  const egressCidrs: string[] = [];
  let terminateTls = false;
  for (let index = 0; index < argv.length; index += 1) {
    const flag = argv[index];
    if (flag === '--terminate-tls') { terminateTls = true; continue; }
    const value = argv[index + 1];
    if (!flag.startsWith('--') || value === undefined) fail(`missing value for ${flag}`);
    index += 1;
    if (flag === '--egress-cidr') egressCidrs.push(value);
    else values.set(flag, value);
  }
  const required = (name: string): string => values.get(name) ?? fail(`${name} is required`);
  const mode = (values.get('--mode') ?? 'split') as 'split' | 'full';
  if (mode !== 'split' && mode !== 'full') fail('--mode must be split or full');
  return {
    latticeHome: path.resolve(values.get('--lattice-home') ?? path.join(process.env.HOME ?? fail('HOME is required'), '.lattice')),
    agent: required('--agent'),
    organization: required('--organization'),
    gateway: required('--gateway'),
    gatewayName: required('--gateway-name'),
    gatewayPin: required('--gateway-pin').toLowerCase(),
    serviceTlsPin: required('--service-tls-pin').toLowerCase(),
    token: required('--enrollment-token'),
    mode,
    out: path.resolve(required('--out')),
    terminateTls,
    egressCidrs,
  };
}

function canonicalService(resource: string): string | null {
  const match = /^lp:\/\/([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.lattice$/.exec(resource);
  return match ? `${match[1]}.lattice` : null;
}

function ipForIndex(index: number): string {
  if (index >= 65_000) fail('legacy service set exceeds migration address budget');
  return `100.96.${Math.floor(index / 254)}.${(index % 254) + 1}`;
}

function readJson(file: string): unknown {
  const bytes = fs.readFileSync(file);
  if (bytes.length > 1024 * 1024) fail(`legacy file exceeds 1 MiB: ${file}`);
  return JSON.parse(bytes.toString('utf8'));
}

function main(): void {
  const args = parseArguments(process.argv.slice(2));
  if (!/^[a-z0-9-]{1,128}$/.test(args.agent)) fail('agent id is not canonical');
  if (!/^[0-9a-f]{64}$/.test(args.gatewayPin) || !/^[0-9a-f]{64}$/.test(args.serviceTlsPin)) {
    fail('TLS pins must be lowercase SHA-256 hex');
  }
  const policyPath = path.join(args.latticeHome, 'policies', `${args.agent}.yaml`);
  const policyBytes = fs.readFileSync(policyPath);
  if (policyBytes.length > 1024 * 1024) fail('legacy policy exceeds 1 MiB');
  const legacy = yaml.load(policyBytes.toString('utf8')) as LegacyPolicy;
  if (legacy.agent !== args.agent) fail('legacy policy principal does not match --agent');

  const servicesDirectory = path.join(args.latticeHome, 'services');
  const serviceNames = fs.readdirSync(servicesDirectory)
    .filter((name) => name.endsWith('.json'))
    .sort();
  const services = new Map<string, { fqdn: string; address: string }>();
  for (const [index, filename] of serviceNames.entries()) {
    const row = readJson(path.join(servicesDirectory, filename)) as { address?: unknown };
    if (typeof row.address !== 'string') continue;
    const fqdn = canonicalService(row.address);
    if (fqdn === null) continue;
    services.set(fqdn, { fqdn, address: ipForIndex(index) });
  }

  const toRules = (rules: LegacyPolicyRule[] | undefined): object[] => (rules ?? []).flatMap((rule) => {
    const fqdn = canonicalService(rule.resource);
    if (fqdn === null) {
      if (rule.resource !== 'internet:*') console.error(`warning: skipped non-network legacy resource ${rule.resource}`);
      return [];
    }
    const service = services.get(fqdn);
    if (!service) fail(`policy refers to an unregistered legacy service: ${fqdn}`);
    return [{ destination: `${service.address}/32`, protocols: ['any'], ports: [], service: fqdn }];
  });
  const allow = toRules(legacy.allow);
  for (const cidr of args.egressCidrs) allow.push({ destination: cidr, protocols: ['any'], ports: [], service: null });
  const deny = toRules(legacy.deny);

  const actionsByService = new Map<string, string[]>();
  for (const rule of legacy.allow ?? []) {
    const fqdn = canonicalService(rule.resource);
    if (fqdn && rule.actions?.length) actionsByService.set(fqdn, [...new Set(rule.actions)].sort());
  }
  if (!args.terminateTls && actionsByService.size > 0) {
    console.error('warning: legacy HTTP actions were not inferred at L3/L4; rerun with --terminate-tls only for a TLS-terminating Gateway');
  }

  const now = new Date();
  const expires = new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000 - 60 * 1000);
  const profileId = crypto.randomUUID();
  const payload = {
    version: 1,
    profile_id: profileId,
    organization_id: args.organization,
    issued_at: now.toISOString(),
    expires_at: expires.toISOString(),
    max_stale_seconds: 86400,
    enrollment_url: 'offline://lattice-netctl',
    enrollment_token: args.token,
    signing_key_id: 'pending',
    control_plane_key_b64: Buffer.alloc(32).toString('base64'),
    tls_root_pem: 'pending',
    client_spki_sha256: '0'.repeat(64),
    require_agent_lease: false,
    agent_lease_public_keys: {},
    revoked_at: null,
    interface: { ipv4: `100.127.${crypto.randomInt(1, 254)}.2/24`, ipv6: null, mtu: 1280 },
    gateways: [{ address: args.gateway, server_name: args.gatewayName, spki_sha256: args.gatewayPin }],
    routes: [...services.values()].map((service) => `${service.address}/32`).concat(args.egressCidrs),
    services: [...services.values()].map((service) => ({
      fqdn: service.fqdn,
      addresses: [service.address],
      gateway: args.gateway,
      tls_spki_sha256: args.serviceTlsPin,
      policy_version: 1,
      http_policy: args.terminateTls && actionsByService.has(service.fqdn)
        ? { terminate_tls: true, allowed_actions: actionsByService.get(service.fqdn) }
        : null,
    })),
    policy: { version: 1, mode: args.mode, allow, deny },
  };
  fs.mkdirSync(path.dirname(args.out), { recursive: true });
  fs.writeFileSync(args.out, `${JSON.stringify(payload, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  console.log(JSON.stringify({ migrated: true, profile_id: profileId, services: services.size, output: args.out }));
}

main();
