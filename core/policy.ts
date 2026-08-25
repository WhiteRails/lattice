import * as crypto from 'crypto';

// ─── Risk table ──────────────────────────────────────────────────────────────

/**
 * Risk level (0–5) per capability class.
 * 0 = safe read, 5 = irreversible / catastrophic.
 */
const RISK: Record<string, number> = {
  'read:public': 0,
  'read:private': 1,
  'write:private': 2,
  'write:external': 2,
  'message:single': 2,
  'message:mass': 4,
  'money:draft': 3,
  'money:execute': 5,
  'code:generate': 2,
  'code:execute': 3,
  'code:deploy': 4,
  'credential:create': 4,
  'cloud:provision': 4,
  'dns:modify': 4,
  'identity:create': 4,
  'legal:commit': 5,
  'physical:operate': 5,
};

// ─── Types ───────────────────────────────────────────────────────────────────

export interface PolicyGrant {
  grant_id: string;
  agent_id: string;
  tool_id: string;
  capability_class: string;
  constraints: {
    requires_human_approval: boolean;
    max_uses?: number;
    expires_at: string;
  };
  granted_by: string;
  granted_at: string;
  use_count: number;
}

export interface PolicyEvalRequest {
  agent_id: string;
  tool_id: string;
  capability_class: string;
  pas_score: number;
  pas_threshold?: number;
}

export interface PolicyDecision {
  decision: 'allow' | 'deny' | 'require_human_approval' | 'rate_limit' | 'pause_agent';
  reason: string;
  risk_level: number;
  grant_id?: string;
}

export function capabilityRiskLevel(capability_class: string): number {
  return RISK[capability_class] ?? 3;
}

// ─── WhitePolicy ─────────────────────────────────────────────────────────────

const DEFAULT_PAS_THRESHOLD = 100;
const DEFAULT_MAX_GRANTS = 100_000;
const DEFAULT_PAGE_SIZE = 1_000;

export interface WhitePolicyOptions {
  /** Maximum grants this policy shard may retain. Capacity exhaustion fails closed. */
  maxGrants?: number;
  /** Default page size for administrative grant enumeration. */
  pageSize?: number;
}

interface ExpiringGrant {
  grantId: string;
  expiresAt: number;
}

function boundedOption(value: number | undefined, fallback: number, min: number, max: number, name: string): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < min || resolved > max) {
    throw new Error(`${name} must be between ${min} and ${max}`);
  }
  return resolved;
}

function grantSelector(agentId: string, toolId: string, capabilityClass: string): string {
  // JSON prevents ambiguous concatenation if an identifier ever contains a delimiter.
  return JSON.stringify([agentId, toolId, capabilityClass]);
}

/**
 * WhitePolicy — grants and evaluates capability permissions for agents.
 *
 * grantCapability() creates a PolicyGrant tied to (agent, tool).
 * evaluate() checks grants, risk level, and Power Accumulation Score to
 * produce a PolicyDecision: allow | deny | require_human_approval | pause_agent.
 */
export class WhitePolicy {
  private readonly grants = new Map<string, PolicyGrant>();
  private readonly grantsBySelector = new Map<string, string>();
  private readonly expiryHeap: ExpiringGrant[] = [];
  private readonly maxGrants: number;
  private readonly pageSize: number;

  constructor(options: WhitePolicyOptions = {}) {
    this.maxGrants = boundedOption(options.maxGrants, DEFAULT_MAX_GRANTS, 1, 1_000_000, 'maxGrants');
    this.pageSize = boundedOption(options.pageSize, DEFAULT_PAGE_SIZE, 1, 10_000, 'pageSize');
  }

  snapshot(): { entries: number; maxGrants: number } {
    this.cleanupExpired(Date.now());
    return { entries: this.grants.size, maxGrants: this.maxGrants };
  }

  // ─── Grant management ───────────────────────────────────────────────────

  grantCapability(params: {
    agent_id: string;
    tool_id: string;
    capability_class: string;
    granted_by: string;
    requires_human_approval?: boolean;
    max_uses?: number;
    expires_in_hours?: number;
  }): PolicyGrant {
    const now = Date.now();
    this.cleanupExpired(now);
    if (this.grants.size >= this.maxGrants) {
      throw new Error(`Policy shard capacity exhausted (${this.maxGrants})`);
    }
    const selector = grantSelector(params.agent_id, params.tool_id, params.capability_class);
    if (this.grantsBySelector.has(selector)) {
      throw new Error('An active grant already exists for this agent, tool, and capability class');
    }
    const grant_id = `grant_${crypto.randomBytes(8).toString('hex')}`;
    const expiresAt = now + (params.expires_in_hours ?? 24) * 3_600_000;
    const grant: PolicyGrant = {
      grant_id,
      agent_id: params.agent_id,
      tool_id: params.tool_id,
      capability_class: params.capability_class,
      constraints: {
        requires_human_approval: params.requires_human_approval ?? false,
        max_uses: params.max_uses,
        expires_at: new Date(expiresAt).toISOString(),
      },
      granted_by: params.granted_by,
      granted_at: new Date(now).toISOString(),
      use_count: 0,
    };
    this.grants.set(grant_id, grant);
    this.grantsBySelector.set(selector, grant_id);
    this.pushExpiry({ grantId: grant_id, expiresAt });
    return grant;
  }

  revokeGrant(grant_id: string): void {
    if (!this.removeGrant(grant_id)) throw new Error(`Grant ${grant_id} not found`);
  }

  // ─── Evaluation ─────────────────────────────────────────────────────────

  getRiskLevel(capability_class: string): number {
    return capabilityRiskLevel(capability_class);
  }

  isGrantValid(grant: PolicyGrant): boolean {
    if (new Date(grant.constraints.expires_at) < new Date()) return false;
    if (grant.constraints.max_uses !== undefined && grant.use_count >= grant.constraints.max_uses) return false;
    return true;
  }

  /**
   * Core policy evaluation. Checks (in order):
   * 1. PAS critical threshold → pause_agent
   * 2. PAS warning threshold  → require_human_approval
   * 3. Valid grant existence   → deny if missing/expired
   * 4. High risk class        → require_human_approval
   * 5. Grant flag             → require_human_approval
   * 6. Default                → allow
   */
  evaluate(request: PolicyEvalRequest): PolicyDecision {
    const threshold = request.pas_threshold ?? DEFAULT_PAS_THRESHOLD;
    const risk_level = this.getRiskLevel(request.capability_class);

    if (request.pas_score >= threshold * 2) {
      return {
        decision: 'pause_agent',
        reason: `PAS ${request.pas_score} critically exceeds threshold ${threshold * 2}`,
        risk_level,
      };
    }

    if (request.pas_score >= threshold) {
      return {
        decision: 'require_human_approval',
        reason: `PAS ${request.pas_score} exceeds threshold ${threshold}`,
        risk_level,
      };
    }

    const grant = this.findGrant(request.agent_id, request.tool_id, request.capability_class);
    if (!grant || !this.isGrantValid(grant)) {
      return {
        decision: 'deny',
        reason: grant
          ? `Grant ${grant.grant_id} is expired or exhausted`
          : `No valid grant for agent=${request.agent_id} tool=${request.tool_id}`,
        risk_level,
      };
    }

    if (risk_level >= 4 || grant.constraints.requires_human_approval) {
      grant.use_count++;
      return {
        decision: 'require_human_approval',
        reason: `Capability '${request.capability_class}' requires human approval (risk ${risk_level})`,
        risk_level,
        grant_id: grant.grant_id,
      };
    }

    grant.use_count++;
    return {
      decision: 'allow',
      reason: `Grant ${grant.grant_id} permits tool ${request.tool_id}`,
      risk_level,
      grant_id: grant.grant_id,
    };
  }

  // ─── Queries ────────────────────────────────────────────────────────────

  private findGrant(agentId: string, toolId: string, capabilityClass: string): PolicyGrant | undefined {
    const selector = grantSelector(agentId, toolId, capabilityClass);
    const id = this.grantsBySelector.get(selector);
    if (!id) return undefined;
    const grant = this.grants.get(id);
    if (!grant || !this.isGrantValid(grant)) {
      this.removeGrant(id);
      return undefined;
    }
    return grant;
  }

  /** A bounded administrative page, never an unbounded policy dump. */
  getGrants(limit = this.pageSize): PolicyGrant[] {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 10_000) {
      throw new Error('limit must be between 1 and 10000');
    }
    this.cleanupExpired(Date.now());
    const page: PolicyGrant[] = [];
    for (const grant of this.grants.values()) {
      page.push(grant);
      if (page.length >= limit) break;
    }
    return page;
  }

  private removeGrant(grantId: string): boolean {
    const grant = this.grants.get(grantId);
    if (!grant) return false;
    this.grants.delete(grantId);
    this.grantsBySelector.delete(grantSelector(grant.agent_id, grant.tool_id, grant.capability_class));
    return true;
  }

  private cleanupExpired(now: number): void {
    while (this.expiryHeap.length > 0 && this.expiryHeap[0]!.expiresAt <= now) {
      const expired = this.popExpiry()!;
      const grant = this.grants.get(expired.grantId);
      if (grant && new Date(grant.constraints.expires_at).getTime() === expired.expiresAt) {
        this.removeGrant(expired.grantId);
      }
    }
  }

  private pushExpiry(value: ExpiringGrant): void {
    this.expiryHeap.push(value);
    let child = this.expiryHeap.length - 1;
    while (child > 0) {
      const parent = Math.floor((child - 1) / 2);
      if (this.expiryHeap[parent]!.expiresAt <= value.expiresAt) break;
      this.expiryHeap[child] = this.expiryHeap[parent]!;
      child = parent;
    }
    this.expiryHeap[child] = value;
  }

  private popExpiry(): ExpiringGrant | undefined {
    const first = this.expiryHeap[0];
    const last = this.expiryHeap.pop();
    if (!first || !last || this.expiryHeap.length === 0) return first;
    let parent = 0;
    while (true) {
      const left = parent * 2 + 1;
      if (left >= this.expiryHeap.length) break;
      const right = left + 1;
      const child = right < this.expiryHeap.length &&
        this.expiryHeap[right]!.expiresAt < this.expiryHeap[left]!.expiresAt ? right : left;
      if (this.expiryHeap[child]!.expiresAt >= last.expiresAt) break;
      this.expiryHeap[parent] = this.expiryHeap[child]!;
      parent = child;
    }
    this.expiryHeap[parent] = last;
    return first;
  }
}
