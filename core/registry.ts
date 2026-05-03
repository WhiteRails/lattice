import * as crypto from 'crypto';
import { RegistryRecord, RegistryRecordSchema, RegistryEvent } from './types';
import { WhiteLog } from './log';

/**
 * WhiteRegistry — federated, name-based identity registry (§7.6).
 *
 * Differences from the old address-based registry:
 * - Records are keyed by human-readable `.white` names
 * - Every mutation (register, key-rotate, revoke) is appended as a
 *   RegistryEvent to a transparency log (§13)
 * - Supports key rotation with log evidence
 * - Answers all 7 registry questions from §7.6
 */
export class WhiteRegistry {
  private records: Map<string, RegistryRecord> = new Map();

  constructor(
    private readonly registryId: string,
    private readonly log?: WhiteLog,
  ) {}

  // ─── Write operations ──────────────────────────────────────────────────────

  register(params: {
    name: string;
    public_key: string;
    service_cert: string;
    gateway_endpoints: string[];
    issuer: string;
    accepted_agent_issuers: string[];
    policy_profile?: string;
  }): string {
    if (this.records.has(params.name)) {
      throw new Error(`Name '${params.name}' is already registered`);
    }
    const record = RegistryRecordSchema.parse({
      name: params.name,
      public_key: params.public_key,
      service_cert: params.service_cert,
      gateway_endpoints: params.gateway_endpoints,
      issuer: params.issuer,
      accepted_agent_issuers: params.accepted_agent_issuers,
      policy_profile: params.policy_profile,
      registered_at: new Date().toISOString(),
      is_revoked: false,
    });
    this.records.set(params.name, record);
    this.emit({ event: 'registered', name: params.name, issuer: params.issuer });
    return params.name;
  }

  /**
   * Rotates the public key for a registered name.
   * Logs a key_rotated transparency event.
   */
  rotateKey(name: string, newPublicKey: string): void {
    const record = this.get(name);
    record.public_key = newPublicKey;
    this.emit({ event: 'key_rotated', name, issuer: record.issuer, new_public_key: newPublicKey });
  }

  /**
   * Marks a name as revoked in the registry.
   * Logs a revoked transparency event.
   */
  revoke(name: string): void {
    const record = this.get(name);
    record.is_revoked = true;
    this.emit({ event: 'revoked', name, issuer: record.issuer });
  }

  /**
   * Updates the policy profile for a name.
   */
  updatePolicyProfile(name: string, policyProfile: string): void {
    const record = this.get(name);
    record.policy_profile = policyProfile;
    this.emit({ event: 'policy_updated', name, issuer: record.issuer });
  }

  // ─── Query operations (§7.6 questions) ────────────────────────────────────

  /** What is this .white name? */
  resolve(name: string): RegistryRecord | undefined {
    return this.records.get(name);
  }

  /** What public key does it map to? */
  getPublicKey(name: string): string | undefined {
    return this.records.get(name)?.public_key;
  }

  /** Who issued it? */
  getIssuer(name: string): string | undefined {
    return this.records.get(name)?.issuer;
  }

  /** Is it revoked? */
  isRevoked(name: string): boolean {
    return this.records.get(name)?.is_revoked ?? false;
  }

  /** What capabilities does it accept? */
  getAcceptedIssuers(name: string): string[] {
    return this.records.get(name)?.accepted_agent_issuers ?? [];
  }

  /** What gateways protect it? */
  getGatewayEndpoints(name: string): string[] {
    return this.records.get(name)?.gateway_endpoints ?? [];
  }

  /** List all registered names. */
  listNames(): string[] {
    return [...this.records.keys()];
  }

  // ─── Private ──────────────────────────────────────────────────────────────

  private get(name: string): RegistryRecord {
    const record = this.records.get(name);
    if (!record) throw new Error(`Name '${name}' not found in registry`);
    return record;
  }

  private emit(event: Omit<RegistryEvent, 'effective_at'>): void {
    const full: RegistryEvent = { ...event, effective_at: new Date().toISOString() };
    this.log?.appendRegistryEvent(full);
  }
}
