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

// ─── WhitePolicy ─────────────────────────────────────────────────────────────

const DEFAULT_PAS_THRESHOLD = 100;

/**
 * WhitePolicy — grants and evaluates capability permissions for agents.
 *
 * grantCapability() creates a PolicyGrant tied to (agent, tool).
 * evaluate() checks grants, risk level, and Power Accumulation Score to
 * produce a PolicyDecision: allow | deny | require_human_approval | pause_agent.
 */
export class WhitePolicy {
  private grants: Map<string, PolicyGrant> = new Map();

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
    const grant_id = `grant_${crypto.randomBytes(8).toString('hex')}`;
    const grant: PolicyGrant = {
      grant_id,
      agent_id: params.agent_id,
      tool_id: params.tool_id,
      capability_class: params.capability_class,
      constraints: {
        requires_human_approval: params.requires_human_approval ?? false,
        max_uses: params.max_uses,
        expires_at: new Date(Date.now() + (params.expires_in_hours ?? 24) * 3_600_000).toISOString(),
      },
      granted_by: params.granted_by,
      granted_at: new Date().toISOString(),
      use_count: 0,
    };
    this.grants.set(grant_id, grant);
    return grant;
  }

  revokeGrant(grant_id: string): void {
    if (!this.grants.has(grant_id)) throw new Error(`Grant ${grant_id} not found`);
    this.grants.delete(grant_id);
  }

  // ─── Evaluation ─────────────────────────────────────────────────────────

  getRiskLevel(capability_class: string): number {
    return RISK[capability_class] ?? 3;
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

    const grant = this.findGrant(request.agent_id, request.tool_id);
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

  private findGrant(agent_id: string, tool_id: string): PolicyGrant | undefined {
    for (const g of this.grants.values()) {
      if (g.agent_id === agent_id && g.tool_id === tool_id) return g;
    }
    return undefined;
  }

  getGrants(): PolicyGrant[] {
    return [...this.grants.values()];
  }
}
