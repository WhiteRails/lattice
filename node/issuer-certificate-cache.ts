import * as crypto from 'crypto';
import type { AgentCert } from '../core/types';
import { verifyAgentIssuerCertificate, type AgentIssuerTrust } from '../core/issuer-trust';
import { BoundedTtlCache } from './bounded-ttl-cache';

const DEFAULT_MAX_ENTRIES = 8_192;
const MAX_TTL_MS = 60_000;

export function issuerCertificateCacheMaxEntriesFromEnv(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.LATTICE_ISSUER_CERTIFICATE_CACHE_MAX_ENTRIES;
  if (raw === undefined || raw.trim() === '') return DEFAULT_MAX_ENTRIES;
  if (!/^[0-9]+$/.test(raw.trim())) throw new Error('LATTICE_ISSUER_CERTIFICATE_CACHE_MAX_ENTRIES must be an integer');
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < 32 || value > 65_536) {
    throw new Error('LATTICE_ISSUER_CERTIFICATE_CACHE_MAX_ENTRIES must be between 32 and 65536');
  }
  return value;
}

/**
 * Bounded cache for issuer signature checks on repeated portable credentials.
 * It is only a performance cache: a certificate's own expiration remains the
 * upper bound and callers still enforce their service/action policy.
 */
export class IssuerCertificateCache {
  private readonly entries: BoundedTtlCache<string, AgentCert>;
  private hits = 0;
  private misses = 0;

  constructor(maxEntries = issuerCertificateCacheMaxEntriesFromEnv()) {
    this.entries = new BoundedTtlCache(maxEntries);
  }

  get size(): number { return this.entries.size; }

  snapshot(): { entries: number; hits: number; misses: number } {
    return { entries: this.entries.size, hits: this.hits, misses: this.misses };
  }

  verify(signed: unknown, trust: AgentIssuerTrust): AgentCert | null {
    const key = cacheKey(signed, trust);
    if (!key) return null;
    const cached = this.entries.get(key);
    if (cached) {
      this.hits++;
      return cached;
    }
    this.misses++;
    const cert = verifyAgentIssuerCertificate(signed, trust);
    if (!cert) return null;
    const remainingMs = cert.expires_at ? new Date(cert.expires_at).getTime() - Date.now() : MAX_TTL_MS;
    if (Number.isFinite(remainingMs) && remainingMs > 0) {
      this.entries.set(key, cert, Math.max(1, Math.min(MAX_TTL_MS, Math.floor(remainingMs))));
    }
    return cert;
  }
}

function cacheKey(signed: unknown, trust: AgentIssuerTrust): string | undefined {
  if (!signed || typeof signed !== 'object') return undefined;
  const signature = (signed as { ca_signature?: unknown }).ca_signature;
  if (typeof signature !== 'string' || signature.length > 1_024) return undefined;
  return crypto.createHash('sha256')
    .update(`${trust.issuer_id}\0${trust.public_key}\0${signature}`, 'utf8')
    .digest('hex');
}
