import { signData, verifySignature } from './identity';
import { hashData } from './envelope';
import { LatticeLog } from './log';
import type { RegistryTransparencyEvent } from './types';

/** Deterministic JSON for signing (sorted object keys, recursively). */
export function stableStringify(value: unknown): string {
  if (value === null) return 'null';
  const t = typeof value;
  if (t === 'string') return JSON.stringify(value);
  if (t === 'number' || t === 'boolean') return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value.map(stableStringify).join(',')}]`;
  }
  if (t === 'object') {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    return `{${keys.map(k => `${JSON.stringify(k)}:${stableStringify(obj[k])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

export const TRUST_MANIFEST_SCHEMA = 'lattice.trust-manifest.v0.1' as const;

export interface TrustManifestIssuerRow {
  issuer_id: string;
  public_key: string;
  allowed_cert_types: string[];
}

export interface TrustManifestBody {
  schema: typeof TRUST_MANIFEST_SCHEMA;
  manifest_id: string;
  issued_at: string;
  issuers: TrustManifestIssuerRow[];
}

export interface SignedTrustManifest {
  manifest: TrustManifestBody;
  /** Governance / federation key id (out-of-band bootstrap). */
  signer_id: string;
  signature: string;
}

export function signTrustManifest(manifest: TrustManifestBody, signerId: string, governancePrivateKey: string): SignedTrustManifest {
  const payload = stableStringify(manifest);
  return {
    manifest,
    signer_id: signerId,
    signature: signData(payload, governancePrivateKey),
  };
}

export function verifyTrustManifestSignature(signed: SignedTrustManifest, governancePublicKey: string): boolean {
  if (signed.manifest.schema !== TRUST_MANIFEST_SCHEMA) return false;
  return verifySignature(stableStringify(signed.manifest), signed.signature, governancePublicKey);
}

export function manifestContentHash(signed: SignedTrustManifest): string {
  return hashData(stableStringify(signed.manifest));
}

/**
 * Append a transparency event that commits the manifest hash to the Merkle log.
 * Verifiers download the manifest bytes, check governance signature, then check this hash matches and is included in a batch.
 */
export function appendManifestCommitEvent(
  log: LatticeLog,
  signed: SignedTrustManifest,
  logOperatorIssuer: string,
  signedByKeyIds: string[],
): RegistryTransparencyEvent {
  const event: RegistryTransparencyEvent = {
    event: 'issuer_manifest_committed',
    manifest_id: signed.manifest.manifest_id,
    manifest_content_hash: manifestContentHash(signed),
    issuer_row_count: signed.manifest.issuers.length,
    effective_at: signed.manifest.issued_at,
    issuer: logOperatorIssuer,
    signed_by: signedByKeyIds,
  };
  log.appendRegistryEvent(event);
  return event;
}
