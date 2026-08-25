import * as crypto from 'crypto';

/**
 * Deterministic highest-random-weight ordering.
 *
 * Every Relay can independently choose the same preferred Gateway replica for
 * an agent without a shared session table. Adding/removing an endpoint moves
 * only the agents whose winning score changes, unlike modulo hashing.
 */
export function rendezvousOrder<T extends string>(candidates: readonly T[], key: string): T[] {
  const unique = [...new Set(candidates)];
  return unique.sort((left, right) => {
    const leftScore = rendezvousScore(key, left);
    const rightScore = rendezvousScore(key, right);
    // Descending score, then lexical order for a total deterministic ordering.
    return Buffer.compare(rightScore, leftScore) || left.localeCompare(right);
  });
}

/** Fixed replication factor keeps discovery lookup and publication bounded. */
export const FEDERATION_ROUTE_REPLICATION = 3;

export function federationReplicaUrls(urls: readonly string[], fqdn: string): string[] {
  return rendezvousOrder(urls, `lattice-federation-v1\u0000${fqdn}`).slice(0, FEDERATION_ROUTE_REPLICATION);
}

function rendezvousScore(key: string, candidate: string): Buffer {
  return crypto.createHash('sha256')
    .update(key, 'utf8')
    .update(Buffer.from([0]))
    .update(candidate, 'utf8')
    .digest();
}
