import * as crypto from 'crypto';
import { AgentCert, WhiteCertificate, WhiteCertificateSchema } from './types';
import { generateKeyPair, KeyPair, signData, verifySignature, createAgentCert } from './identity';
import { hashObject } from './envelope';
import { RevocationNetwork } from './revocation';

/**
 * A certificate that has been signed by a WhiteCA.
 */
export interface SignedCert<T extends WhiteCertificate> {
  cert: T;
  ca_signature: string;
  ca_cert_id: string;
}

/**
 * WhiteCA — issues, tracks and revokes certificates for all WhiteNet actor types.
 *
 * Each CA instance generates its own Ed25519 key pair. Certificates are signed
 * by the CA private key and can be verified against the CA public key.
 */
export class WhiteCA {
  private readonly caKeyPair: KeyPair;
  private readonly caId: string;
  private issuedCerts: Map<string, SignedCert<WhiteCertificate>> = new Map();

  constructor(caId: string) {
    this.caId = caId;
    this.caKeyPair = generateKeyPair();
  }

  get publicKey(): string {
    return this.caKeyPair.publicKey;
  }

  get id(): string {
    return this.caId;
  }

  // ─── Private helpers ──────────────────────────────────────────────────────

  private sign<T extends WhiteCertificate>(cert: T): SignedCert<T> {
    const ca_signature = signData(JSON.stringify(cert), this.caKeyPair.privateKey);
    const signed: SignedCert<T> = { cert, ca_signature, ca_cert_id: this.caId };
    this.issuedCerts.set(cert.id, signed as SignedCert<WhiteCertificate>);
    return signed;
  }

  private makeCert(type: string, expiresInDays?: number): WhiteCertificate {
    const now = new Date();
    return WhiteCertificateSchema.parse({
      id: `cert:${type}:${crypto.randomBytes(8).toString('hex')}`,
      type,
      issuer: this.caId,
      public_key: generateKeyPair().publicKey,
      issued_at: now.toISOString(),
      expires_at: expiresInDays
        ? new Date(now.getTime() + expiresInDays * 86_400_000).toISOString()
        : undefined,
    });
  }

  // ─── Issuance ─────────────────────────────────────────────────────────────

  issueOrgCert(params: { org_id: string; expires_in_days?: number }): SignedCert<WhiteCertificate> {
    return this.sign(this.makeCert('OrgCert', params.expires_in_days));
  }

  issueAgentCert(params: {
    agent_id: string;
    owner_org: string;
    agent_type: string;
    version: string;
    public_key: string;
    allowed_capability_classes: string[];
    forbidden_capability_classes: string[];
    expires_in_days?: number;
  }): SignedCert<AgentCert> {
    const cert = createAgentCert({ ...params, issuer: this.caId });
    return this.sign(cert);
  }

  issueServiceCert(params: { service_id: string; expires_in_days?: number }): SignedCert<WhiteCertificate> {
    return this.sign(this.makeCert('ServiceCert', params.expires_in_days));
  }

  issueGatewayCert(params: { gateway_id: string; expires_in_days?: number }): SignedCert<WhiteCertificate> {
    return this.sign(this.makeCert('GatewayCert', params.expires_in_days));
  }

  issueRuntimeCert(params: { runtime_id: string; expires_in_days?: number }): SignedCert<WhiteCertificate> {
    return this.sign(this.makeCert('RuntimeCert', params.expires_in_days));
  }

  issueToolCert(params: { tool_id: string; expires_in_days?: number }): SignedCert<WhiteCertificate> {
    return this.sign(this.makeCert('ToolCert', params.expires_in_days));
  }

  // ─── Revocation ───────────────────────────────────────────────────────────

  /**
   * Revokes a previously issued certificate by its cert.id.
   * Publishes a signed revocation record to the provided RevocationNetwork.
   */
  revoke(certId: string, reason: string, revocationNetwork: RevocationNetwork) {
    const signed = this.issuedCerts.get(certId);
    if (!signed) throw new Error(`Certificate ${certId} not found in CA ${this.caId}`);
    return revocationNetwork.publishRevocation({
      target_type: signed.cert.type,
      target_hash: hashObject(signed.cert),
      revoked_by: this.caId,
      reason,
      issuerPrivateKey: this.caKeyPair.privateKey,
    });
  }

  // ─── Verification ─────────────────────────────────────────────────────────

  verifyCert(signedCert: SignedCert<WhiteCertificate>): boolean {
    return verifySignature(
      JSON.stringify(signedCert.cert),
      signedCert.ca_signature,
      this.caKeyPair.publicKey,
    );
  }

  getIssuedCerts(): Map<string, SignedCert<WhiteCertificate>> {
    return this.issuedCerts;
  }
}
