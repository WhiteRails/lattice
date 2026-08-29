/**
 * Lattice node YAML config (~/.lattice/node.yaml).
 */
import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';
import { z } from 'zod';
import { LATTICE_DIR } from './state';
import type { AgentIssuerTrust } from '../core/issuer-trust';

export const NODE_CONFIG_FILENAME = 'node.yaml';

/** Default path for routing cache (FQDN metadata + signatures). */
export const DEFAULT_ROUTING_CACHE_PATH = path.join(LATTICE_DIR, 'routing-cache.json');

export const LATTICE_NODE_ROLES = ['entry', 'relay', 'gateway'] as const;
export type LatticeNodeRole = (typeof LATTICE_NODE_ROLES)[number];
/** Local bootstrap/failover sets, never a representation of global membership. */
export const MAX_UPSTREAM_RELAYS = 16;
export const MAX_RENDEZVOUS_RELAYS = 16;
export const MAX_FEDERATION_BOOTSTRAPS = 64;
export const MAX_LOCAL_SERVICES = 256;
export const MAX_ENTRY_AGENT_ISSUERS = 64;

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

const nodeCryptoSchema = z.object({
  backend: z.enum(['local', 'plugin']).optional(),
  pluginCommand: z.string().min(1).max(4_096).optional(),
  keyDir: z.string().min(1).max(4_096).optional(),
}).strict().optional();

const circuitSchema = z.object({
  /** Protocol constants are bounded here so a peer cannot negotiate weaker values. */
  maxAgeSeconds: z.number().int().min(60).max(600).optional(),
  maxStreams: z.number().int().min(1).max(100).optional(),
  maxConcurrentStreams: z.number().int().min(1).max(32).optional(),
  guardLifetimeDays: z.number().int().min(1).max(30).optional(),
  /** Accepted only when every configured endpoint is loopback. */
  allowSingleOperatorLoopbackTests: z.boolean().optional(),
  /** Allows local TLS-less socket fixtures, never public endpoints. */
  allowInsecureLoopbackTests: z.boolean().optional(),
}).strict().optional();

const upstreamRelaySchema = z.union([
  z.string().url(),
  z.object({
    label: z.string().min(1),
    url: z.string().url(),
  }).strict(),
]);

const agentIssuerTrustSchema = z.object({
  issuer_id: z.string().min(1).max(256),
  public_key: z.string().min(32).max(8_192),
}).strict();

const gatewayIssuerGrantSchema = z.object({
  issuer_id: z.string().min(1).max(256),
  public_key: z.string().min(32).max(8_192),
  services: z.array(z.object({
    address: z.string().min(1).max(512),
    actions: z.array(z.string().min(1).max(128)).min(1).max(64),
  }).strict()).min(1).max(MAX_LOCAL_SERVICES),
}).strict();

const latticeNodeConfigSchema = z.object({
  nodeId: z.string().min(1).optional(),
  roles: z.array(z.enum(LATTICE_NODE_ROLES)).min(1).optional(),
  distributedMesh: z.boolean().optional(),
  overlayProtocol: z.enum(['onion-v1']).optional(),
  crypto: nodeCryptoSchema,
  circuit: circuitSchema,

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
  upstreamRelays: z.array(upstreamRelaySchema).max(MAX_UPSTREAM_RELAYS).optional(),

  /** Issuer roots accepted by Entry for portable agent certificates. */
  agentTrust: z.object({
    issuers: z.array(agentIssuerTrustSchema).max(MAX_ENTRY_AGENT_ISSUERS),
  }).strict().optional(),

  /** Label of lattice node registry entry matching `upstreamRelays[0]` (for pubkey lookup). */
  primaryUpstreamRelayLabel: z.string().min(1).optional(),

  registry: z
    .object({
      chain: chainSchema,
      cacheFile: z.string().min(1).optional(),
      /** HTTP URLs of federation registry servers to poll for lp:// routing. */
      federationUrls: z.array(z.string().url()).max(MAX_FEDERATION_BOOTSTRAPS).optional(),
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
      /** Relay endpoints to dial when mode=hidden (labels are mandatory in mesh mode). */
      rendezvousRelays: z.array(upstreamRelaySchema).max(MAX_RENDEZVOUS_RELAYS).optional(),
      /** TTL in seconds for federation announcements (default 300). */
      announceTtlSeconds: z.number().int().positive().optional(),
      /** Compact issuer-to-service authorisation for agents without local policy files. */
      issuerGrants: z.array(gatewayIssuerGrantSchema).max(MAX_ENTRY_AGENT_ISSUERS).optional(),
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

  /**
   * Declarative service definitions used by `lattice up`.
   * Each entry maps an lp:// address to an internal HTTP backend.
   */
  services: z
    .array(
      z.object({
        address: z.string().min(1),   // e.g. lp://echo.lattice
        target: z.string().url(),     // e.g. http://127.0.0.1:9001
        port: z.number().int().positive().optional(), // gateway WS port (auto-assigned if omitted)
      }).strict(),
    ).max(MAX_LOCAL_SERVICES)
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
  if (cfg.distributedMesh && cfg.overlayProtocol !== 'onion-v1') {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['overlayProtocol'],
      message: 'overlayProtocol onion-v1 is required when distributedMesh is true',
    });
  }
  if (cfg.crypto?.backend === 'plugin' && !cfg.crypto.pluginCommand?.trim()) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['crypto', 'pluginCommand'],
      message: 'pluginCommand is required when crypto.backend is plugin',
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
export interface GatewayIssuerGrant {
  issuer_id: string;
  public_key: string;
  services: Array<{ address: string; actions: string[] }>;
}

/** Small, operator-authorised issuer roots; never a list of every agent key. */
export function resolveEntryTrustedAgentIssuers(cfg: LatticeNodeYaml | null): AgentIssuerTrust[] {
  return cfg?.agentTrust?.issuers ?? [];
}

export function resolveGatewayIssuerGrants(cfg: LatticeNodeYaml | null): GatewayIssuerGrant[] {
  return cfg?.gateway?.issuerGrants ?? [];
}
export type NodeChainConfig = { rpcUrl: string; contractAddress: string };

export interface OnionCircuitConfig {
  maxAgeSeconds: number;
  maxStreams: number;
  maxConcurrentStreams: number;
  guardLifetimeDays: number;
  allowSingleOperatorLoopbackTests: boolean;
  allowInsecureLoopbackTests: boolean;
}

export function resolveOnionCircuitConfig(cfg: LatticeNodeYaml | null): OnionCircuitConfig {
  return {
    maxAgeSeconds: cfg?.circuit?.maxAgeSeconds ?? 600,
    maxStreams: cfg?.circuit?.maxStreams ?? 100,
    maxConcurrentStreams: cfg?.circuit?.maxConcurrentStreams ?? 32,
    guardLifetimeDays: cfg?.circuit?.guardLifetimeDays ?? 30,
    allowSingleOperatorLoopbackTests: cfg?.circuit?.allowSingleOperatorLoopbackTests ?? false,
    allowInsecureLoopbackTests: cfg?.circuit?.allowInsecureLoopbackTests ?? false,
  };
}

export function onionOverlayEffective(cfg: LatticeNodeYaml | null): boolean {
  return distributedMeshEffective(cfg) && cfg?.overlayProtocol === 'onion-v1';
}

export function assertOnionOverlayRequired(cfg: LatticeNodeYaml | null, distributedMesh = distributedMeshEffective(cfg)): void {
  if (distributedMesh && cfg?.overlayProtocol !== 'onion-v1') {
    throw new Error('ROUTE_ENCRYPTION_REQUIRED: distributedMesh requires overlayProtocol onion-v1');
  }
}

export function assertOnionWebSocketUrls(cfg: LatticeNodeYaml | null, urls: readonly string[]): void {
  if (!onionOverlayEffective(cfg)) return;
  const allowLoopback = resolveOnionCircuitConfig(cfg).allowInsecureLoopbackTests;
  for (const value of urls) {
    const url = new URL(value);
    if (url.protocol === 'wss:') continue;
    if (url.protocol === 'ws:' && allowLoopback && isLoopbackHostname(url.hostname)) continue;
    throw new Error(`ONION_WSS_REQUIRED: distributed Onion v1 endpoint must use wss:// (${value})`);
  }
}

export function assertOnionListenerTls(cfg: LatticeNodeYaml | null, bindHost: string, role: LatticeNodeRole): void {
  if (!onionOverlayEffective(cfg) || role === 'entry') return;
  if (cfg?.tls?.certFile?.trim() && cfg?.tls?.keyFile?.trim()) return;
  if (resolveOnionCircuitConfig(cfg).allowInsecureLoopbackTests && isLoopbackHostname(bindHost)) return;
  throw new Error(`ONION_WSS_REQUIRED: ${role} listener requires tls.certFile and tls.keyFile`);
}

function isLoopbackHostname(hostname: string): boolean {
  const host = hostname.replace(/^\[|]$/g, '').toLowerCase();
  return host === '127.0.0.1' || host === '::1' || host === 'localhost';
}

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

export function resolveRendezvousRelays(cfg: LatticeNodeYaml | null): UpstreamRelay[] {
  return (cfg?.gateway?.rendezvousRelays ?? []).map(r =>
    typeof r === 'string' ? { url: r.trim() } : { label: r.label.trim(), url: r.url.trim() },
  );
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
