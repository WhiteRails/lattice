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
  upsertRoutingPayload,
  lpFromFqdn,
  ROUTING_PAYLOAD_VERSION,
  type RoutingPayload,
} from './routing-cache';
import { LOCAL_FALLBACK_WS_REGISTRY } from './local-relay-registry';
import { getOrCreateOverlayKeyPair } from './state';
import { fetchFederationRoutes } from './federation-registry';

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
}

function isNamespaceUnknown(ns: {
  ownerIssuerId: string;
}): boolean {
  return ns.ownerIssuerId === ethers.ZeroHash || !ns.ownerIssuerId;
}

export class LpGatewayResolver {
  constructor(
    private readonly cfg: LatticeNodeYaml | null,
    private readonly chain: { rpcUrl: string; contractAddress: string } | null,
  ) {}

  /**
   * Poll configured federation registries for a route.
   * Caches valid results into local routing-cache so subsequent calls are fast.
   */
  private async resolveFederation(fqdn: string): Promise<RoutingPayload | null> {
    const urls = resolveFederationUrls(this.cfg);
    if (!urls.length) return null;
    const now = Date.now();
    for (const url of urls) {
      const resp = await fetchFederationRoutes(url);
      if (!resp?.routes) continue;
      const entry = resp.routes[fqdn];
      if (!entry) continue;
      // Skip expired entries
      if (new Date(entry.expiresAt).getTime() < now) continue;
      if (!entry.payload.gatewayEndpoints.length) continue;
      // Cache locally so future resolves skip the HTTP round-trip
      try {
        upsertRoutingPayload(this.cfg, entry.payload);
      } catch {
        // cache write failure is non-fatal
      }
      return entry.payload;
    }
    return null;
  }

  async resolveRelayPubkey(remoteLabel?: string): Promise<string | undefined> {
    if (!remoteLabel?.trim()) return undefined;
    try {
      if (!this.chain) {
        const file = readRoutingCacheFile(this.cfg);
        return file?.latticeNodes[remoteLabel.trim()]?.overlayPubKeyB64;
      }
      const rec = await chainGetLatticeNode(this.chain.rpcUrl, this.chain.contractAddress, remoteLabel.trim());
      if (!rec?.active) return undefined;
      return rec.overlayPubKeyB64;
    } catch {
      return undefined;
    }
  }

  async resolveDestination(lpDestination: string): Promise<ResolvedGatewayRoute> {
    const fqdn = fqdnFromLpAddress(lpDestination);
    const cached = lookupRoutingPayload(this.cfg, fqdn, { requireLocalSig: !this.chain });

    if (!this.chain) {
      const mesh = distributedMeshEffective(this.cfg);
      let payload = cached;

      // Step 2: Try federation registries if cache miss
      if (!payload || !payload.gatewayEndpoints.length) {
        const fedPayload = await this.resolveFederation(fqdn);
        if (fedPayload) payload = fedPayload;
      }

      // Step 3: LOCAL_FALLBACK for single-machine dev (no mesh, no federation)
      if ((!payload || !payload.gatewayEndpoints.length) && !mesh) {
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
          };
        }
      }
      if (!payload || !payload.gatewayEndpoints.length) {
        throw new LpRoutingNotFoundError(
          `No chain config and no routing cache row for ${fqdn}. ` +
          `Configure registry.federationUrls in node.yaml, populate ~/.lattice/routing-cache.json, or disable distributedMesh.`,
        );
      }
      const metaHex = routingCommitmentHex(payload);
      return {
        fqdn,
        lpDestination: lpDestination.includes('lp://') ? lpDestination : `lp://${fqdn}`,
        gatewayNodeLabel: payload.gatewayNodeLabel,
        gatewayPubKeyB64: payload.gatewayPubKeyB64,
        gatewayEndpoints: [...payload.gatewayEndpoints],
        metadataHash: metaHex,
        serviceCertHash: '',
      };
    }

    const ns = await chainGetNamespace(this.chain.rpcUrl, this.chain.contractAddress, fqdn);
    if (!ns.active || isNamespaceUnknown(ns)) {
      throw new LpRoutingNotFoundError(`Unknown or inactive Lattice namespace on-chain: ${fqdn}`);
    }

    const chainMeta = ns.metadataHash === ethers.ZeroHash ? '' : String(ns.metadataHash).toLowerCase();
    const svc = ns.serviceCertHash === ethers.ZeroHash ? '' : String(ns.serviceCertHash).toLowerCase();
    const mesh = distributedMeshEffective(this.cfg);

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
      throw new LpRoutingNotFoundError(`No gateway endpoints cached for ${fqdn}`);
    }

    const metaHex = routingCommitmentHex(payload);
    return {
      fqdn,
      lpDestination: lpDestination.includes('lp://') ? lpDestination : `lp://${fqdn}`,
      gatewayNodeLabel: payload.gatewayNodeLabel,
      gatewayPubKeyB64: payload.gatewayPubKeyB64,
      gatewayEndpoints: [...payload.gatewayEndpoints],
      metadataHash: metaHex,
      serviceCertHash: svc,
    };
  }
}
