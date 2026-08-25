import {
  RevocationRecord,
  RevocationRecordSchema,
  RevocationReasonCode,
} from './types';
import { signData, verifySignature } from './identity';

function compositeKey(target_type: string, target_hash: string): string {
  return `${target_type}::${target_hash}`;
}

export interface RevocationNetworkOptions {
  maxEntries?: number;
  pageSize?: number;
}

const DEFAULT_MAX_ENTRIES = 100_000;
const DEFAULT_PAGE_SIZE = 1_000;

function boundedOption(value: number | undefined, fallback: number, min: number, max: number, name: string): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < min || resolved > max) {
    throw new Error(`${name} must be between ${min} and ${max}`);
  }
  return resolved;
}

export class RevocationNetwork {
  private readonly revocations = new Map<string, RevocationRecord>();
  private readonly targetHashes = new Set<string>();
  private readonly maxEntries: number;
  private readonly pageSize: number;

  constructor(options: RevocationNetworkOptions = {}) {
    this.maxEntries = boundedOption(options.maxEntries, DEFAULT_MAX_ENTRIES, 1, 1_000_000, 'maxEntries');
    this.pageSize = boundedOption(options.pageSize, DEFAULT_PAGE_SIZE, 1, 10_000, 'pageSize');
  }

  snapshot(): { entries: number; maxEntries: number } {
    return { entries: this.revocations.size, maxEntries: this.maxEntries };
  }

  /**
   * Publishes a revocation record (certificate, signing key, or other target).
   */
  publishRevocation(params: {
    target_type: string;
    target_hash: string;
    revoked_by: string;
    reason: string;
    issuerPrivateKey: string;
    target_key_id?: string;
    reason_code?: RevocationReasonCode;
    effective_at?: string;
    suspected_from?: string;
    compromise_window?: { suspected_from: string; confirmed_at: string };
    evidence_hash?: string;
  }): RevocationRecord {
    const record: Omit<RevocationRecord, 'signature'> = {
      schema: 'lattice.revocation.v0.2',
      target_type: params.target_type,
      target_hash: params.target_hash,
      target_key_id: params.target_key_id,
      revoked_by: params.revoked_by,
      reason: params.reason,
      reason_code: params.reason_code,
      effective_at: params.effective_at ?? new Date().toISOString(),
      suspected_from: params.suspected_from,
      compromise_window: params.compromise_window,
      evidence_hash: params.evidence_hash,
    };

    const signature = signData(JSON.stringify(record), params.issuerPrivateKey);
    const finalRecord = RevocationRecordSchema.parse({ ...record, signature });
    const key = compositeKey(params.target_type, params.target_hash);
    if (!this.revocations.has(key) && this.revocations.size >= this.maxEntries) {
      // A valid revocation is never evicted to make room. The publisher must
      // select another shard rather than weakening freshness decisions.
      throw new Error(`Revocation shard capacity exhausted (${this.maxEntries})`);
    }
    this.revocations.set(key, finalRecord);
    this.targetHashes.add(params.target_hash);
    return finalRecord;
  }

  isRevoked(target_type: string, target_hash: string): boolean {
    return this.revocations.has(compositeKey(target_type, target_hash));
  }

  /** Lookup by hash when the caller does not have the target type. */
  isRevokedAnyTarget(target_hash: string): boolean {
    return this.targetHashes.has(target_hash);
  }

  getRevocation(target_type: string, target_hash: string): RevocationRecord | undefined {
    return this.revocations.get(compositeKey(target_type, target_hash));
  }
  /** A shard page, never a global revocation dump. */
  listRevocations(limit = this.pageSize): RevocationRecord[] {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 10_000) {
      throw new Error('limit must be between 1 and 10000');
    }
    const page: RevocationRecord[] = [];
    for (const record of this.revocations.values()) {
      page.push(record);
      if (page.length >= limit) break;
    }
    return page;
  }

  verifyRevocation(record: RevocationRecord, issuerPublicKey: string): boolean {
    const { signature, ...unsignedPart } = record;
    return verifySignature(JSON.stringify(unsignedPart), signature, issuerPublicKey);
  }
}
