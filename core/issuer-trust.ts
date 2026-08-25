import { AgentCertSchema, type AgentCert } from './types';
import { isCertValid, verifySignature } from './identity';

export interface AgentIssuerTrust {
  issuer_id: string;
  public_key: string;
}

export interface TrustedAgentIssuer extends AgentIssuerTrust {
  /** Stable agent certificate subject accepted by this policy principal. */
  subject: string;
}

/** Verifies a current AgentCert against a configured issuer root. */
export function verifyAgentIssuerCertificate(signed: unknown, trust: AgentIssuerTrust): AgentCert | null {
  if (!signed || typeof signed !== 'object') return null;
  const record = signed as { cert?: unknown; ca_signature?: unknown; ca_cert_id?: unknown };
  if (typeof record.ca_signature !== 'string' || record.ca_cert_id !== trust.issuer_id) return null;
  const cert = AgentCertSchema.safeParse(record.cert);
  if (!cert.success || !isCertValid(cert.data)) return null;
  if (cert.data.issuer !== trust.issuer_id || !verifySignature(JSON.stringify(cert.data), record.ca_signature, trust.public_key)) {
    return null;
  }
  return cert.data;
}

/** Verifies a complete issuer-signed AgentCert binding for one policy principal. */
export function verifyTrustedAgentIssuer(
  signed: unknown,
  trust: TrustedAgentIssuer,
  agentPublicKey: string,
): boolean {
  const cert = verifyAgentIssuerCertificate(signed, trust);
  return cert !== null && cert.agent_id === trust.subject && cert.public_key === agentPublicKey;
}
