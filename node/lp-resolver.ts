/**
 * Hybrid resolver: LatticeChain namespaces + federation registries + local signed routing cache hints.
 *
 * Resolution order:
 *   1. On-chain LatticeChain namespace (if chain configured)
 *   2. Federation registries (if registry.federationUrls configured)
 *   3. Local routing-cache file (HMAC-signed)
 *   4. LOCAL_FALLBACK_WS_REGISTRY (local dev only, no distributedMesh)
 */
import { ethers } from 'ethers';
import type { LatticeNodeYaml } from './node-config';
import { distributedMeshEffective, resolveFederationUrls } from './node-config';
import { chainGetLatticeNode, chainGetNamespace } from './chain';
import {
  fqdnFromLpAddress,
  lookupRoutingPayload,
  routingCommitmentHex,
  readRoutingCacheFile,
  normalizeRoutingPayload,
  lpFromFqdn,
  ROUTING_PAYLOAD_VERSION,
  assertEncryptedRoutingPayload,
  type RoutingPayload,
} from './routing-cache';
import { LOCAL_FALLBACK_WS_REGISTRY } from './local-relay-registry';
import { getOrCreateOverlayKeyPair, loadCA } from './state';
import { fetchFederationRoute } from './federation-registry';
import { isSelfAuthAddress, pubkeyFromSelfAuthFqdn, deriveSelfAuthAddress } from './self-auth';
import { federationReplicaUrls } from './rendezvous';
import { BoundedTtlCache } from './bounded-ttl-cache';

export class LpRoutingNotFoundError extends Error {
  constructor(msg: string) {
    super(msg);
    this.name = 'LpRoutingNotFoundError';
  }
}

export interface ResolvedGatewayRoute {
  fqdn: string;
  lpDestination: string;
  gatewayNodeLabel?: string;
  gatewayPubKeyB64: string;
  gatewayEndpoints: string[];
  metadataHash: string;
  serviceCertHash: string;
  gatewayEncryptionKeyId?: string;
  gatewayEncryptionPubKeyB64Url?: string;
  hpkeSuite?: string;
  delivery?: RoutingPayload['delivery'];
}

interface ChainNamespaceRecord {
  ownerIssuerId: string;
  serviceCertHash: string;
  metadataHash: string;
  active: boolean;
  namespaceAdmin: string;
  publicAccess: boolean;
  credentialMask: number;
  minAssuranceLevel: number;
}

export interface ResolverCacheOptions {
  chainTtlMs?: number;
  chainMaxEntries?: number;
}

const DEFAULT_CHAIN_CACHE_TTL_MS = 30_000;
const DEFAULT_CHAIN_CACHE_MAX_ENTRIES = 10_000;
const FEDERATION_CACHE_MAX_ENTRIES = 10_000;
const FEDERATION_NEGATIVE_CACHE_TTL_MS = 5_000;
const FEDERATION_MAX_CACHE_TTL_MS = 300_000;

/** Bounds RPC load for on-chain namespace/node reads in a single cell. */
export function resolverCacheOptionsFromEnv(env: NodeJS.ProcessEnv = process.env): Required<ResolverCacheOptions> {
  return {
    chainTtlMs: boundedResolverCacheValue(
      env.LATTICE_CHAIN_CACHE_TTL_MS, DEFAULT_CHAIN_CACHE_TTL_MS, 1_000, 300_000, 'LATTICE_CHAIN_CACHE_TTL_MS',
    ),
    chainMaxEntries: boundedResolverCacheValue(
      env.LATTICE_CHAIN_CACHE_MAX_ENTRIES, DEFAULT_CHAIN_CACHE_MAX_ENTRIES, 32, 100_000, 'LATTICE_CHAIN_CACHE_MAX_ENTRIES',
    ),
  };
}

function boundedResolverCacheValue(raw: string | undefined, fallback: number, min: number, max: number, name: string): number {
  if (raw === undefined || raw.trim() === '') return fallback;
  if (!/^[0-9]+$/.test(raw.trim())) throw new Error(`${name} must be an integer`);
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < min || value > max) throw new Error(`${name} must be between ${min} and ${max}`);
  return value;
}

function isNamespaceUnknown(ns: {
  ownerIssuerId: string;
}): boolean {
  return ns.ownerIssuerId === ethers.ZeroHash || !ns.ownerIssuerId;
}

export class LpGatewayResolver {
  // Cache misses too: an invalid name must not query its registry replicas on
  // every request. Federation remains only an online routing hint, so both the
  // positive and negative entries are bounded and expire quickly.
  private readonly federationCache = new BoundedTtlCache<string, RoutingPayload | null>(FEDERATION_CACHE_MAX_ENTRIES);
  private readonly chainTtlMs: number;
  private readonly chainNamespaceCache: BoundedTtlCache<string, ChainNamespaceRecord>;
  private readonly chainNodeCache: BoundedTtlCache<string, string | null>;
  constructor(
    private readonly cfg: LatticeNodeYaml | null,
    private readonly chain: { rpcUrl: string; contractAddress: string } | null,
    cacheOptions: ResolverCacheOptions = resolverCacheOptionsFromEnv(),
  ) {
    const options = {
      chainTtlMs: cacheOptions.chainTtlMs ?? DEFAULT_CHAIN_CACHE_TTL_MS,
      chainMaxEntries: cacheOptions.chainMaxEntries ?? DEFAULT_CHAIN_CACHE_MAX_ENTRIES,
    };
    if (!Number.isSafeInteger(options.chainTtlMs) || options.chainTtlMs < 1_000 || options.chainTtlMs > 300_000) {
      throw new Error('chainTtlMs must be between 1000 and 300000');
    }
    if (!Number.isSafeInteger(options.chainMaxEntries) || options.chainMaxEntries < 1 || options.chainMaxEntries > 100_000) {
      throw new Error('chainMaxEntries must be between 1 and 100000');
    }
    this.chainTtlMs = options.chainTtlMs;
    this.chainNamespaceCache = new BoundedTtlCache(options.chainMaxEntries);
    this.chainNodeCache = new BoundedTtlCache(options.chainMaxEntries);
  }

  /**
   * Poll configured federation registries for a route.
   * Federation is online discovery only; it is never re-sealed into the local
   * operator-authorised routing cache.
   */
  private async resolveFederation(fqdn: string): Promise<RoutingPayload | null> {
    const urls = resolveFederationUrls(this.cfg);
    if (!urls.length) return null;
    const now = Date.now();
    const cached = this.federationCache.get(fqdn);
    if (cached !== undefined) return cached;
    // A name is replicated to a fixed small set of registry shards. Never
    // fan out a cache miss to every global registry.
    for (const url of federationReplicaUrls(urls, fqdn)) {
      const entry = await fetchFederationRoute(url, fqdn, { overlaySecret: loadCA().overlaySecret });
      if (!entry) continue;
      // Skip expired entries
      if (new Date(entry.expiresAt).getTime() < now) continue;
      if (!routingPayloadDeliverable(entry.payload)) continue;
      const payload = normalizeRoutingPayload(entry.payload);
      if (payload.fqdn !== fqdn) continue;
      const expiresAtMs = new Date(entry.expiresAt).getTime();
      if (!Number.isFinite(expiresAtMs) || expiresAtMs <= now) continue;
      // Do not retain a remotely supplied hint longer than five minutes even
      // when its advertised expiration is much farther away.
      this.federationCache.set(fqdn, payload, Math.min(expiresAtMs - now, FEDERATION_MAX_CACHE_TTL_MS), now);
      return payload;
    }
    this.federationCache.set(fqdn, null, FEDERATION_NEGATIVE_CACHE_TTL_MS, now);
    return null;
  }

  async resolveRelayPubkey(remoteLabel?: string): Promise<string | undefined> {
    if (!remoteLabel?.trim()) return undefined;
    try {
      if (!this.chain) {
        const file = readRoutingCacheFile(this.cfg);
        return file?.latticeNodes[remoteLabel.trim()]?.overlayPubKeyB64;
      }
      const label = remoteLabel.trim();
      const cached = this.chainNodeCache.get(label);
      if (cached !== undefined) return cached ?? undefined;
      const rec = await chainGetLatticeNode(this.chain.rpcUrl, this.chain.contractAddress, label);
      const pubkey = rec?.active ? rec.overlayPubKeyB64 : null;
      // Negative caching prevents a stream of invalid labels from becoming a
      // stream of chain RPCs. It remains bounded and expires quickly.
      this.chainNodeCache.set(label, pubkey, this.chainTtlMs);
      return pubkey ?? undefined;
    } catch {
      return undefined;
    }
  }

  /**
   * Resolve a self-authenticating lp://<hex>.id address.
   * The pubkey is embedded in the address — no chain lookup needed.
   * Routing-cache/federation provide the endpoints; pubkey provides identity.
   */
  private async resolveSelfAuth(fqdn: string, lpDestination: string): Promise<ResolvedGatewayRoute> {
    const pubkeyB64 = pubkeyFromSelfAuthFqdn(fqdn);
    if (!pubkeyB64) throw new LpRoutingNotFoundError(`Invalid self-auth address: ${fqdn}`);

    // The .id key establishes identity, not authority for arbitrary endpoints.
    // Only an operator-authenticated local route may name where to dial.
    const payload = lookupRoutingPayload(this.cfg, fqdn, { requireLocalSig: true });

    if (!payload || !routingPayloadDeliverable(payload)) {
      throw new LpRoutingNotFoundError(
        `No routing found for self-auth address ${fqdn}. ` +
        `The gateway must announce lp://${fqdn} to federation or routing-cache.`,
      );
    }

    // Verify the routing payload's pubkey matches the address (trust verification)
    if (deriveSelfAuthAddress(payload.gatewayPubKeyB64) !== fqdn) {
      throw new LpRoutingNotFoundError(
        `Self-auth pubkey mismatch for ${fqdn}: ` +
        `routing entry pubkey does not match address. Possible hijack attempt.`,
      );
    }
    if (distributedMeshEffective(this.cfg)) assertEncryptedRoutingPayload(payload);

    return {
      fqdn,
      lpDestination,
      gatewayNodeLabel: payload.gatewayNodeLabel,
      gatewayPubKeyB64: pubkeyB64,
      gatewayEndpoints: [...payload.gatewayEndpoints],
      metadataHash: routingCommitmentHex(payload),
      serviceCertHash: '',
      gatewayEncryptionKeyId: payload.gatewayEncryptionKeyId,
      gatewayEncryptionPubKeyB64Url: payload.gatewayEncryptionPubKeyB64Url,
      hpkeSuite: payload.hpkeSuite,
      delivery: payload.delivery,
    };
  }

  async resolveDestination(lpDestination: string): Promise<ResolvedGatewayRoute> {
    const fqdn = fqdnFromLpAddress(lpDestination);

    // Self-authenticating .id address — pubkey IS the identity, no chain needed
    if (isSelfAuthAddress(fqdn)) {
      return this.resolveSelfAuth(fqdn, lpDestination);
    }

    const mesh = distributedMeshEffective(this.cfg);
    const cached = lookupRoutingPayload(this.cfg, fqdn, { requireLocalSig: !this.chain });

    if (!this.chain) {
      let payload = cached;

      // Step 2: Federation registries — but ONLY allowed without chain in non-mesh mode.
      // In distributed mesh, signed routing-cache is the trust anchor; federation without
      // on-chain namespace verification can be hijacked by any authenticated node.
      if (!payload || !routingPayloadDeliverable(payload)) {
        if (mesh) {
          throw new LpRoutingNotFoundError(
            `Distributed mesh requires a signed routing-cache entry or chain config for ${fqdn}. ` +
            `Run: lattice routing announce --fqdn ${fqdn} (or set registry.chain in node.yaml). ` +
            `Without on-chain verification, federation alone cannot be trusted as a namespace authority.`,
          );
        }
        const fedPayload = await this.resolveFederation(fqdn);
        if (fedPayload) payload = fedPayload;
      }

      // Step 3: LOCAL_FALLBACK for single-machine dev (no mesh, no federation)
      if ((!payload || !routingPayloadDeliverable(payload)) && !mesh) {
        const canon = lpFromFqdn(fqdn);
        const ws = LOCAL_FALLBACK_WS_REGISTRY[canon];
        if (ws) {
          const pk = getOrCreateOverlayKeyPair().publicKey;
          const metaHint: RoutingPayload = {
            version: ROUTING_PAYLOAD_VERSION,
            fqdn,
            gatewayPubKeyB64: pk,
            gatewayEndpoints: [ws],
          };
          return {
            fqdn,
            lpDestination: canon,
            gatewayNodeLabel: undefined,
            gatewayPubKeyB64: pk,
            gatewayEndpoints: [ws],
            metadataHash: routingCommitmentHex(metaHint),
            serviceCertHash: '',
            gatewayEncryptionKeyId: metaHint.gatewayEncryptionKeyId,
            gatewayEncryptionPubKeyB64Url: metaHint.gatewayEncryptionPubKeyB64Url,
            hpkeSuite: metaHint.hpkeSuite,
            delivery: metaHint.delivery,
          };
        }
      }
      if (!payload || !routingPayloadDeliverable(payload)) {
        throw new LpRoutingNotFoundError(
          `No chain config and no routing cache row for ${fqdn}. ` +
          `Configure registry.federationUrls in node.yaml, populate ~/.lattice/routing-cache.json, or disable distributedMesh.`,
        );
      }
      const metaHex = routingCommitmentHex(payload);
      if (mesh) assertEncryptedRoutingPayload(payload);
      return {
        fqdn,
        lpDestination: lpDestination.includes('lp://') ? lpDestination : `lp://${fqdn}`,
        gatewayNodeLabel: payload.gatewayNodeLabel,
        gatewayPubKeyB64: payload.gatewayPubKeyB64,
        gatewayEndpoints: [...payload.gatewayEndpoints],
        metadataHash: metaHex,
        serviceCertHash: '',
        gatewayEncryptionKeyId: payload.gatewayEncryptionKeyId,
        gatewayEncryptionPubKeyB64Url: payload.gatewayEncryptionPubKeyB64Url,
        hpkeSuite: payload.hpkeSuite,
        delivery: payload.delivery,
      };
    }

    let ns = this.chainNamespaceCache.get(fqdn);
    if (!ns) {
      ns = await chainGetNamespace(this.chain.rpcUrl, this.chain.contractAddress, fqdn);
      this.chainNamespaceCache.set(fqdn, ns, this.chainTtlMs);
    }
    if (!ns.active || isNamespaceUnknown(ns)) {
      throw new LpRoutingNotFoundError(`Unknown or inactive Lattice namespace on-chain: ${fqdn}`);
    }

    const chainMeta = ns.metadataHash === ethers.ZeroHash ? '' : String(ns.metadataHash).toLowerCase();
    const svc = ns.serviceCertHash === ethers.ZeroHash ? '' : String(ns.serviceCertHash).toLowerCase();

    let payload = cached;
    if (mesh && !chainMeta) {
      throw new LpRoutingNotFoundError(`Missing on-chain routing metadataHash for distributed namespace ${fqdn}`);
    }
    if (chainMeta) {
      if (!payload) {
        throw new LpRoutingNotFoundError(
          `Missing local routing-cache entry for committed namespace ${fqdn}. Run lattice gateway routing announce (or lattice routing announce).`,
        );
      }
      const canon = routingCommitmentHex(payload as RoutingPayload);
      if (canon !== chainMeta) {
        throw new LpRoutingNotFoundError(`Routing-cache commitment mismatch chain metadataHash for ${fqdn}`);
      }
    }

    if (!payload || payload.gatewayEndpoints.length === 0) {
      if (payload?.delivery?.mode !== 'hidden') {
        throw new LpRoutingNotFoundError(`No gateway endpoints cached for ${fqdn}`);
      }
    }
    if (mesh) assertEncryptedRoutingPayload(payload);

    const metaHex = routingCommitmentHex(payload);
    return {
      fqdn,
      lpDestination: lpDestination.includes('lp://') ? lpDestination : `lp://${fqdn}`,
      gatewayNodeLabel: payload.gatewayNodeLabel,
      gatewayPubKeyB64: payload.gatewayPubKeyB64,
      gatewayEndpoints: [...payload.gatewayEndpoints],
      metadataHash: metaHex,
      serviceCertHash: svc,
      gatewayEncryptionKeyId: payload.gatewayEncryptionKeyId,
      gatewayEncryptionPubKeyB64Url: payload.gatewayEncryptionPubKeyB64Url,
      hpkeSuite: payload.hpkeSuite,
      delivery: payload.delivery,
    };
  }
}

function routingPayloadDeliverable(payload: RoutingPayload): boolean {
  return payload.gatewayEndpoints.length > 0 ||
    (payload.delivery?.mode === 'hidden' && payload.delivery.rendezvous.length > 0);
}
