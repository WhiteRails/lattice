import { RevocationRecord, RevocationRecordSchema } from './types';
import { hashObject } from './envelope';
import { signData, verifySignature } from './identity';

export class RevocationNetwork {
  private revocations: Map<string, RevocationRecord> = new Map();

  /**
   * Publishes a revocation record.
   */
  publishRevocation(params: {
    target_type: string;
    target_hash: string;
    revoked_by: string;
    reason: string;
    issuerPrivateKey: string;
  }): RevocationRecord {
    const record: Omit<RevocationRecord, 'signature'> = {
      schema: 'whitenet.revocation.v0.1',
      target_type: params.target_type,
      target_hash: params.target_hash,
      revoked_by: params.revoked_by,
      reason: params.reason,
      effective_at: new Date().toISOString(),
    };

    const signature = signData(JSON.stringify(record), params.issuerPrivateKey);
    const finalRecord = RevocationRecordSchema.parse({ ...record, signature });

    this.revocations.set(params.target_hash, finalRecord);
    return finalRecord;
  }

  /**
   * Checks if a target (identified by its hash) is revoked.
   */
  isRevoked(targetHash: string): boolean {
    return this.revocations.has(targetHash);
  }

  /**
   * Gets the revocation record for a target hash.
   */
  getRevocation(targetHash: string): RevocationRecord | undefined {
    return this.revocations.get(targetHash);
  }

  /**
   * Verifies a revocation record.
   */
  verifyRevocation(record: RevocationRecord, issuerPublicKey: string): boolean {
    const { signature, ...unsignedPart } = record;
    return verifySignature(JSON.stringify(unsignedPart), signature, issuerPublicKey);
  }
}
