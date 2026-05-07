/**
 * Lattice node YAML config (~/.lattice/node.yaml).
 */
import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';
import { z } from 'zod';
import { LATTICE_DIR } from './state';

export const NODE_CONFIG_FILENAME = 'node.yaml';

/** Default path for routing cache (FQDN metadata + signatures). */
export const DEFAULT_ROUTING_CACHE_PATH = path.join(LATTICE_DIR, 'routing-cache.json');

export const LATTICE_NODE_ROLES = ['entry', 'relay', 'gateway'] as const;
export type LatticeNodeRole = (typeof LATTICE_NODE_ROLES)[number];

const bindHostPort = z.union([
  z.string().regex(/^(\d+\.\d+\.\d+\.\d+|::|\[.*]|[a-zA-Z._-]+):(\d+)$/, 'host:port'),
  z.string().regex(/^:(\d+)$/, ':port shorthand'),
]).optional();

const chainSchema = z
  .object({
    rpcUrl: z.string().min(1),
    contractAddress: z.string().min(1),
  })
  .strict()
  .optional();

const tlsSchema = z
  .object({
    certFile: z.string().min(1).optional(),
    keyFile: z.string().min(1).optional(),
    /** PEM CA bundle for pinning self-signed relays / gateways when not using LE. */
    caFile: z.string().min(1).optional(),
  })
  .strict()
  .optional();

const upstreamRelaySchema = z.union([
  z.string().url(),
  z.object({
    label: z.string().min(1),
    url: z.string().url(),
  }).strict(),
]);

const latticeNodeConfigSchema = z.object({
  nodeId: z.string().min(1).optional(),
  roles: z.array(z.enum(LATTICE_NODE_ROLES)).min(1).optional(),
  distributedMesh: z.boolean().optional(),

  bind: z
    .object({
      entry: bindHostPort,
      relay: bindHostPort,
      gateway: bindHostPort,
    })
    .strict()
    .optional(),

  /** Canonical public URLs advertised for this node */
  public: z
    .object({
      entry: z.string().url().optional(),
      relay: z.string().url().optional(),
      gateway: z.string().url().optional(),
    })
    .strict()
    .optional(),

  /** Prefer first URL; failover on transient connect failures (Entry outbound). */
  upstreamRelays: z.array(upstreamRelaySchema).optional(),

  /** Label of lattice node registry entry matching `upstreamRelays[0]` (for pubkey lookup). */
  primaryUpstreamRelayLabel: z.string().min(1).optional(),

  registry: z
    .object({
      chain: chainSchema,
      cacheFile: z.string().min(1).optional(),
      /** HTTP URLs of federation registry servers to poll for lp:// routing. */
      federationUrls: z.array(z.string().url()).optional(),
    })
    .strict()
    .optional(),

  /** Hidden-service / rendezvous config for gateways that dial out to relays. */
  gateway: z
    .object({
      /** 'public' (default) = listen for inbound WS; 'hidden' = dial out to rendezvousRelays. */
      mode: z.enum(['public', 'hidden']).optional(),
      /** lp:// address this gateway serves (required for hidden mode). */
      hiddenServiceAddress: z.string().optional(),
      /** Relay URLs to dial when mode=hidden (rendezvous relays). */
      rendezvousRelays: z.array(z.string().url()).optional(),
      /** TTL in seconds for federation announcements (default 300). */
      announceTtlSeconds: z.number().int().positive().optional(),
    })
    .strict()
    .optional(),

  /** Run a local federation registry HTTP server on this node. */
  federation: z
    .object({
      serve: z.boolean().optional(),
      bindHostPort: bindHostPort,
    })
    .strict()
    .optional(),

  tls: tlsSchema,
}).strict().superRefine((cfg, ctx) => {
  if (cfg.distributedMesh && !cfg.nodeId?.trim()) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['nodeId'],
      message: 'nodeId is required when distributedMesh is true',
    });
  }
  if (cfg.gateway?.mode === 'hidden') {
    if (!cfg.gateway.hiddenServiceAddress?.trim()) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['gateway', 'hiddenServiceAddress'],
        message: 'hiddenServiceAddress is required when gateway.mode is hidden',
      });
    }
    if (!cfg.gateway.rendezvousRelays?.length) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['gateway', 'rendezvousRelays'],
        message: 'rendezvousRelays must be non-empty when gateway.mode is hidden',
      });
    }
  }
});

export type LatticeNodeYaml = z.infer<typeof latticeNodeConfigSchema>;
export type UpstreamRelay = { label?: string; url: string };
export type NodeChainConfig = { rpcUrl: string; contractAddress: string };

export function nodeConfigPath(): string {
  return path.join(LATTICE_DIR, NODE_CONFIG_FILENAME);
}

export function loadNodeConfig(): LatticeNodeYaml | null {
  const p = nodeConfigPath();
  if (!fs.existsSync(p)) return null;
  const raw = fs.readFileSync(p, 'utf-8');
  const doc = yaml.load(raw);
  const parsed = latticeNodeConfigSchema.safeParse(doc);
  if (!parsed.success) throw new Error(`Invalid ${NODE_CONFIG_FILENAME}: ${parsed.error.message}`);
  return parsed.data;
}

export function saveNodeConfig(sample: LatticeNodeYaml): void {
  const p = nodeConfigPath();
  const dir = path.dirname(p);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  fs.writeFileSync(p, yaml.dump(sample), { mode: 0o600 });
}

/** Parse bind like "0.0.0.0:7777" or ":7777". */
export function parseBindHostPort(b: string | undefined, fallbackHost: string, fallbackPort: number): { host: string; port: number } {
  if (!b) return { host: fallbackHost, port: fallbackPort };
  const trimmed = b.trim();
  if (trimmed.startsWith(':')) {
    const port = parseInt(trimmed.slice(1), 10);
    if (!Number.isFinite(port)) throw new Error(`Invalid bind port: ${b}`);
    return { host: fallbackHost, port };
  }
  const lastColon = trimmed.lastIndexOf(':');
  if (trimmed.startsWith('[')) {
    const end = trimmed.indexOf(']:');
    if (end !== -1) {
      const host = trimmed.slice(1, end);
      const port = parseInt(trimmed.slice(end + 2), 10);
      if (!Number.isFinite(port)) throw new Error(`Invalid bind: ${b}`);
      return { host: `[${host}]`, port };
    }
    throw new Error(`Invalid IPv6 bind: ${b}`);
  }
  if (lastColon <= 0) throw new Error(`Invalid bind host:port: ${b}`);
  const host = trimmed.slice(0, lastColon);
  const port = parseInt(trimmed.slice(lastColon + 1), 10);
  if (!Number.isFinite(port)) throw new Error(`Invalid bind port: ${b}`);
  return { host, port };
}

export function distributedMeshEffective(cfg: LatticeNodeYaml | null): boolean {
  if (process.env.LATTICE_DISTRIBUTED_MESH?.trim() === '1') return true;
  return Boolean(cfg?.distributedMesh);
}

export function requireDistributedNodeId(cfg: LatticeNodeYaml | null, distributedMesh: boolean): string | undefined {
  const id = cfg?.nodeId?.trim();
  if (distributedMesh && !id) throw new Error('nodeId is required when distributedMesh is enabled');
  return id || undefined;
}

export function normalizeUpstreamRelays(cfg: LatticeNodeYaml | null, fallback: string[] = []): UpstreamRelay[] {
  const raw = cfg?.upstreamRelays?.length ? cfg.upstreamRelays : fallback;
  const primary = cfg?.primaryUpstreamRelayLabel?.trim();
  return raw.map((r, idx) => {
    if (typeof r === 'string') {
      return { url: r, label: idx === 0 ? primary : undefined };
    }
    return { label: r.label.trim(), url: r.url.trim() };
  });
}

export function resolveNodeChainConfig(cfg: LatticeNodeYaml | null): NodeChainConfig | null {
  const chainCfg =
    cfg?.registry?.chain?.rpcUrl?.trim() && cfg?.registry?.chain?.contractAddress?.trim()
      ? { rpcUrl: cfg.registry.chain.rpcUrl.trim(), contractAddress: cfg.registry.chain.contractAddress.trim() }
      : null;

  const rpcOverride = process.env.LATTICE_CHAIN_RPC_URL?.trim();
  const contractOverride = process.env.LATTICE_CHAIN_ADDRESS?.trim();
  if (!rpcOverride && !contractOverride) return chainCfg;

  const rpcUrl = (rpcOverride || chainCfg?.rpcUrl || '').trim();
  const contractAddress = (contractOverride || chainCfg?.contractAddress || '').trim();
  if (!rpcUrl || !contractAddress) {
    throw new Error('Partial chain config (need both RPC URL and contract address, or omit entirely)');
  }
  return { rpcUrl, contractAddress };
}

export type ResolvedBind = ReturnType<typeof parseBindHostPort>;

export function resolveFederationUrls(cfg: LatticeNodeYaml | null): string[] {
  return cfg?.registry?.federationUrls ?? [];
}

export function resolveGatewayMode(cfg: LatticeNodeYaml | null): 'public' | 'hidden' {
  return cfg?.gateway?.mode ?? 'public';
}

export function resolveRendezvousRelays(cfg: LatticeNodeYaml | null): string[] {
  return cfg?.gateway?.rendezvousRelays ?? [];
}

export function resolveHiddenServiceAddress(cfg: LatticeNodeYaml | null): string | undefined {
  return cfg?.gateway?.hiddenServiceAddress?.trim() || undefined;
}

export function resolveFederationServe(cfg: LatticeNodeYaml | null): { serve: boolean; bindHostPort: string } {
  return {
    serve: cfg?.federation?.serve ?? false,
    bindHostPort: cfg?.federation?.bindHostPort ?? '127.0.0.1:9000',
  };
}
