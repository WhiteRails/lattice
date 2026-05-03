import * as crypto from 'crypto';
import {
  EmergencyKeyCompromiseEventSchema,
  FreezeSubjectEventSchema,
  KeyPurpose,
  KeyRecord,
  KeyRecordSchema,
  KeyRotationEventSchema,
  KeyStatus,
  RecoveryPolicy,
  RecoveryPolicySchema,
  RegistryRecord,
  RegistryRecordSchema,
  RegistryTransparencyEvent,
  SubjectFreezeEffects,
  SubjectFreezeState,
  UnfreezeSubjectEventSchema,
} from './types';
import { LatticeLog } from './log';
import { deriveDefaultSubjectId, hashSubjectForLatticeSuffix } from './addressing';

function hashPublicKeyPem(pem: string): string {
  return crypto.createHash('sha256').update(pem, 'utf8').digest('hex');
}

function nowIso(): string {
  return new Date().toISOString();
}

/**
 * LatticeRegistry — federated registry: stable subject, multiple rotatable keys.
 *
 * Every mutation is appended as a RegistryTransparencyEvent to the transparency log.
 */
export class LatticeRegistry {
  private records: Map<string, RegistryRecord> = new Map();
  private orgToSubject: Map<string, string> = new Map();

  constructor(
    private readonly registryId: string,
    private readonly log?: LatticeLog,
  ) {}

  register(params: {
    name: string;
    subject_id?: string;
    public_key: string;
    signing_key_id?: string;
    /** Override initial key validity start (tests / migrations). Defaults to now. */
    valid_from?: string;
    key_purpose?: KeyPurpose;
    service_cert: string;
    gateway_endpoints: string[];
    issuer: string;
    accepted_agent_issuers: string[];
    policy_profile?: string;
    linked_org_id?: string;
    recovery_policy?: RecoveryPolicy;
  }): string {
    if (this.records.has(params.name)) {
      throw new Error(`Name '${params.name}' is already registered`);
    }
    const subject_id = params.subject_id ?? deriveDefaultSubjectId(params.name);
    const keyId = params.signing_key_id ?? 'key_initial_signing';
    const purpose = params.key_purpose ?? 'SIGNING';
    const key: KeyRecord = KeyRecordSchema.parse({
      key_id: keyId,
      subject_id,
      key_purpose: purpose,
      public_key: params.public_key,
      public_key_hash: hashPublicKeyPem(params.public_key),
      valid_from: params.valid_from ?? nowIso(),
      valid_until: undefined,
      status: 'ACTIVE',
    });

    const record = RegistryRecordSchema.parse({
      subject_id,
      name: params.name,
      keys: [key],
      service_cert: params.service_cert,
      gateway_endpoints: params.gateway_endpoints,
      issuer: params.issuer,
      accepted_agent_issuers: params.accepted_agent_issuers,
      policy_profile: params.policy_profile,
      linked_org_id: params.linked_org_id,
      recovery_policy: params.recovery_policy
        ? RecoveryPolicySchema.parse(params.recovery_policy)
        : undefined,
      registered_at: nowIso(),
      is_revoked: false,
    });

    this.records.set(params.name, record);
    if (params.linked_org_id) {
      this.orgToSubject.set(params.linked_org_id, subject_id);
    }

    this.emit({
      event: 'registered',
      subject_id,
      name: params.name,
      effective_at: nowIso(),
      issuer: params.issuer,
    });
    return params.name;
  }

  /**
   * Planned rotation: overlap window where old signing key stays valid until `old_key_valid_until`.
   */
  rotateSigningKey(params: {
    name: string;
    old_key_id: string;
    new_key_id: string;
    new_public_key: string;
    effective_at: string;
    old_key_valid_until: string;
    signed_by: string[];
  }): void {
    const record = this.get(params.name);
    const old = record.keys.find(k => k.key_id === params.old_key_id && k.key_purpose === 'SIGNING');
    if (!old) throw new Error(`Old signing key '${params.old_key_id}' not found`);

    old.status = 'DEPRECATED';
    old.valid_until = params.old_key_valid_until;

    const neu: KeyRecord = KeyRecordSchema.parse({
      key_id: params.new_key_id,
      subject_id: record.subject_id,
      key_purpose: 'SIGNING',
      public_key: params.new_public_key,
      public_key_hash: hashPublicKeyPem(params.new_public_key),
      valid_from: params.effective_at,
      valid_until: undefined,
      status: 'ACTIVE',
    });
    record.keys.push(neu);

    this.emit(
      KeyRotationEventSchema.parse({
        event: 'KEY_ROTATION',
        subject_id: record.subject_id,
        name: record.name,
        old_key_id: params.old_key_id,
        new_key_id: params.new_key_id,
        effective_at: params.effective_at,
        old_key_valid_until: params.old_key_valid_until,
        signed_by: params.signed_by,
        issuer: record.issuer,
      }),
    );
  }

  /** Mark old signing key retired after overlap (normal lifecycle). */
  retireSigningKey(name: string, key_id: string, retired_at: string): void {
    const record = this.get(name);
    const k = record.keys.find(x => x.key_id === key_id && x.key_purpose === 'SIGNING');
    if (!k) throw new Error(`Signing key '${key_id}' not found`);
    k.status = 'RETIRED';
    k.valid_until = k.valid_until ?? retired_at;
    this.emit({
      event: 'policy_updated',
      subject_id: record.subject_id,
      name: record.name,
      effective_at: retired_at,
      issuer: record.issuer,
    });
  }

  emergencyKeyCompromise(params: {
    name: string;
    compromised_key_id: string;
    compromise_window: { suspected_from: string; confirmed_at: string };
    new_key_id: string;
    new_public_key: string;
    requires_reaudit: boolean;
    signed_by: string[];
    threshold?: string;
    effective_at: string;
  }): void {
    const record = this.get(params.name);
    const k = record.keys.find(x => x.key_id === params.compromised_key_id);
    if (!k) throw new Error(`Key '${params.compromised_key_id}' not found`);
    k.status = 'REVOKED_COMPROMISED';
    k.valid_until = params.compromise_window.confirmed_at;

    const neu: KeyRecord = KeyRecordSchema.parse({
      key_id: params.new_key_id,
      subject_id: record.subject_id,
      key_purpose: 'SIGNING',
      public_key: params.new_public_key,
      public_key_hash: hashPublicKeyPem(params.new_public_key),
      valid_from: params.effective_at,
      valid_until: undefined,
      status: 'ACTIVE',
    });
    record.keys.push(neu);

    this.emit(
      EmergencyKeyCompromiseEventSchema.parse({
        event: 'EMERGENCY_KEY_COMPROMISE',
        subject_id: record.subject_id,
        name: record.name,
        compromised_key_id: params.compromised_key_id,
        status: 'revoked_compromised',
        compromise_window: params.compromise_window,
        new_key_id: params.new_key_id,
        requires_reaudit: params.requires_reaudit,
        signed_by: params.signed_by,
        threshold: params.threshold,
        issuer: record.issuer,
        effective_at: params.effective_at,
      }),
    );
  }

  freezeSubject(params: {
    name: string;
    reason: string;
    effect: SubjectFreezeEffects;
    signed_by: string[];
    effective_at: string;
  }): void {
    const record = this.get(params.name);
    const state: SubjectFreezeState = {
      active: true,
      reason: params.reason,
      effect: params.effect,
      effective_at: params.effective_at,
    };
    record.freeze = state;
    this.emit(
      FreezeSubjectEventSchema.parse({
        event: 'FREEZE_SUBJECT',
        subject_id: record.subject_id,
        name: record.name,
        reason: params.reason,
        effect: params.effect,
        signed_by: params.signed_by,
        issuer: record.issuer,
        effective_at: params.effective_at,
      }),
    );
  }

  unfreezeSubject(params: { name: string; signed_by: string[]; effective_at: string }): void {
    const record = this.get(params.name);
    record.freeze = undefined;
    this.emit(
      UnfreezeSubjectEventSchema.parse({
        event: 'UNFREEZE_SUBJECT',
        subject_id: record.subject_id,
        name: record.name,
        signed_by: params.signed_by,
        issuer: record.issuer,
        effective_at: params.effective_at,
      }),
    );
  }

  /** True if org's linked subject is frozen with block_high_risk_actions. */
  isOrgHighRiskFrozen(linkedOrgId: string): boolean {
    const sid = this.orgToSubject.get(linkedOrgId);
    if (!sid) return false;
    const rec = [...this.records.values()].find(r => r.subject_id === sid);
    if (!rec?.freeze?.active) return false;
    return rec.freeze.effect.block_high_risk_actions === true;
  }

  /** True if new certificate issuance should be blocked (per freeze effect). */
  isNewCertIssuanceBlockedForOrg(linkedOrgId: string): boolean {
    const sid = this.orgToSubject.get(linkedOrgId);
    if (!sid) return false;
    const rec = [...this.records.values()].find(r => r.subject_id === sid);
    if (!rec?.freeze?.active) return false;
    return rec.freeze.effect.block_new_cert_issuance === true;
  }

  updateRecoveryPolicy(name: string, policy: RecoveryPolicy): void {
    const record = this.get(name);
    record.recovery_policy = RecoveryPolicySchema.parse(policy);
    this.emit({
      event: 'policy_updated',
      subject_id: record.subject_id,
      name: record.name,
      effective_at: nowIso(),
      issuer: record.issuer,
    });
  }

  updatePolicyProfile(name: string, policyProfile: string): void {
    const record = this.get(name);
    record.policy_profile = policyProfile;
    this.emit({
      event: 'policy_updated',
      subject_id: record.subject_id,
      name: record.name,
      effective_at: nowIso(),
      issuer: record.issuer,
    });
  }

  revoke(name: string): void {
    const record = this.get(name);
    record.is_revoked = true;
    this.emit({
      event: 'revoked',
      subject_id: record.subject_id,
      name: record.name,
      effective_at: nowIso(),
      issuer: record.issuer,
    });
  }

  resolve(name: string): RegistryRecord | undefined {
    return this.records.get(name);
  }

  /** Active SIGNING public key PEM for this name (for wire crypto). */
  getPublicKey(name: string): string | undefined {
    const k = this.getActiveSigningKey(name);
    return k?.public_key;
  }

  getActiveSigningKey(name: string): KeyRecord | undefined {
    const record = this.records.get(name);
    if (!record) return undefined;
    const now = Date.now();
    const candidates = record.keys.filter(k => {
      if (k.key_purpose !== 'SIGNING') return false;
      if (k.status !== 'ACTIVE' && k.status !== 'DEPRECATED') return false;
      const from = new Date(k.valid_from).getTime();
      const until = k.valid_until !== undefined ? new Date(k.valid_until).getTime() : Number.POSITIVE_INFINITY;
      return now >= from && now < until;
    });
    if (candidates.length === 0) return undefined;
    const preferActive = candidates.filter(c => c.status === 'ACTIVE');
    const pool = preferActive.length > 0 ? preferActive : candidates;
    return pool.reduce((best, cur) =>
      new Date(cur.valid_from).getTime() > new Date(best.valid_from).getTime() ? cur : best,
    pool[0]);
  }

  getIssuer(name: string): string | undefined {
    return this.records.get(name)?.issuer;
  }

  isRevoked(name: string): boolean {
    return this.records.get(name)?.is_revoked ?? false;
  }

  getAcceptedIssuers(name: string): string[] {
    return this.records.get(name)?.accepted_agent_issuers ?? [];
  }

  getGatewayEndpoints(name: string): string[] {
    return this.records.get(name)?.gateway_endpoints ?? [];
  }

  listNames(): string[] {
    return [...this.records.keys()];
  }

  latticeSuffixForName(name: string): string {
    const r = this.get(name);
    return hashSubjectForLatticeSuffix(r.subject_id);
  }

  private get(name: string): RegistryRecord {
    const record = this.records.get(name);
    if (!record) throw new Error(`Name '${name}' not found in registry`);
    return record;
  }

  private emit(event: RegistryTransparencyEvent): void {
    this.log?.appendRegistryEvent(event);
  }
}
