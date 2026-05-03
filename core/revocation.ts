import {
  RevocationRecord,
  RevocationRecordSchema,
  RevocationReasonCode,
} from './types';
import { signData, verifySignature } from './identity';

function compositeKey(target_type: string, target_hash: string): string {
  return `${target_type}::${target_hash}`;
}

export class RevocationNetwork {
  private revocations: Map<string, RevocationRecord> = new Map();

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
    this.revocations.set(compositeKey(params.target_type, params.target_hash), finalRecord);
    return finalRecord;
  }

  isRevoked(target_type: string, target_hash: string): boolean {
    return this.revocations.has(compositeKey(target_type, target_hash));
  }

  /** Back-compat: treat hash as unique key across types (last write wins if types collide). */
  isRevokedLegacy(target_hash: string): boolean {
    for (const k of this.revocations.keys()) {
      if (k.endsWith(`::${target_hash}`)) return true;
    }
    return false;
  }

  getRevocation(target_type: string, target_hash: string): RevocationRecord | undefined {
    return this.revocations.get(compositeKey(target_type, target_hash));
  }
  listRevocations(): RevocationRecord[] {
    return [...this.revocations.values()];
  }

  verifyRevocation(record: RevocationRecord, issuerPublicKey: string): boolean {
    const { signature, ...unsignedPart } = record;
    return verifySignature(JSON.stringify(unsignedPart), signature, issuerPublicKey);
  }
}
