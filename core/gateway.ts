import { SAAE, AgentCert, CapabilityToken, DelegationGrant, IntentAnchor, PASScore } from './types';
import { isCertValid, signData, verifySignature } from './identity';
import { createSAAEBase, hashObject } from './envelope';
import { RevocationNetwork } from './revocation';
import { PowerAccumulationTracker } from './pas';
import { WhitePolicy, capabilityRiskLevel } from './policy';
import { LatticeLog } from './log';
import { LatticeRegistry } from './registry';
import { SignedCert } from './ca';
import * as crypto from 'crypto';

export function toolCallSignaturePayload(params: {
  agent_id: string;
  delegation: DelegationGrant;
  intent: IntentAnchor;
  capability: CapabilityToken;
  capability_class?: string;
  tool_id: string;
  action_type: string;
  action_parameters: any;
  runtime_cert_hash: string;
}): string {
  return JSON.stringify({
    agent_id: params.agent_id,
    delegation: params.delegation,
    intent: params.intent,
    capability: params.capability,
    capability_class: params.capability_class,
    tool_id: params.tool_id,
    action_type: params.action_type,
    action_parameters: params.action_parameters,
    runtime_cert_hash: params.runtime_cert_hash,
  });
}

export class LatticeGateway {
  private registeredAgents: Map<string, AgentCert> = new Map();
  private revocationNetwork?: RevocationNetwork;
  private pasTracker?: PowerAccumulationTracker;
  private policy?: WhitePolicy;
  private log?: LatticeLog;
  private registry?: LatticeRegistry;

  constructor(public gatewayId: string, private gatewayPrivateKey: string) {}

  setRevocationNetwork(rn: RevocationNetwork) {
    this.revocationNetwork = rn;
  }

  setPASTracker(pas: PowerAccumulationTracker) {
    this.pasTracker = pas;
  }

  setPolicy(policy: WhitePolicy) {
    this.policy = policy;
  }

  setLog(log: LatticeLog) {
    this.log = log;
  }

  setRegistry(registry: LatticeRegistry) {
    this.registry = registry;
  }

  /**
   * Registers an agent certificate in the gateway.
   */
  registerAgent(signedCert: SignedCert<AgentCert>, caPublicKey: string) {
    if (!verifySignature(JSON.stringify(signedCert.cert), signedCert.ca_signature, caPublicKey)) {
      throw new Error('Invalid CA signature on agent certificate');
    }
    const cert = signedCert.cert;
    if (!isCertValid(cert)) {
      throw new Error('Attempted to register an invalid or expired certificate');
    }
    this.registeredAgents.set(cert.agent_id, cert);
  }

  /**
   * Mediates a tool call request from an agent.
   */
  async mediateToolCall(params: {
    agent_id: string;
    agent_signature: string;
    /** ISO-8601 timestamp the agent used when constructing the agent_action_signature payload. */
    action_timestamp: string;
    delegation: DelegationGrant;
    intent: IntentAnchor;
    capability: CapabilityToken;
    capability_class?: string;
    tool_id: string;
    action_type: string;
    action_parameters: any;
    runtime_cert_hash: string;
    pas_updates?: Partial<PASScore['factors']>;
  }): Promise<SAAE> {
    const cert = this.registeredAgents.get(params.agent_id);
    if (!cert) {
      throw new Error(`Agent ${params.agent_id} is not registered`);
    }

    // Check revocation
    if (this.revocationNetwork?.isRevoked('AgentCert', hashObject(cert))) {
      throw new Error(`Agent certificate for ${params.agent_id} has been revoked`);
    }

    const capabilityClass =
      params.capability_class
      ?? (params.capability.capability_id.split(':').slice(1).join(':') || 'default');
    const riskLevel = this.policy
      ? this.policy.getRiskLevel(capabilityClass)
      : capabilityRiskLevel(capabilityClass);

    if (this.registry?.isOrgHighRiskFrozen(cert.owner_org) && riskLevel >= 4) {
      throw new Error(
        `Subject frozen: high-risk actions blocked for organization ${cert.owner_org}`,
      );
    }

    // 1. Policy & Capability check
    let decision: 'allow' | 'deny' | 'require_human_approval' = 'allow';

    try {
      this.checkPolicy(cert, params.capability, params.tool_id);
      this.checkAuthority(cert, params.delegation, params.intent, params.capability, {
        action_type: params.action_type,
        tool_id: params.tool_id,
        capability_class: capabilityClass,
      });
      if (params.capability.constraints.requires_human_approval) {
        decision = 'require_human_approval';
      }
    } catch (e: any) {
      decision = 'deny';
      throw e;
    }

    // 2. Policy engine evaluation (preferred path when available)
    if (this.policy) {
      const pasScore = this.pasTracker?.getScore(params.agent_id)?.score ?? 0;
      const pd = this.policy.evaluate({
        agent_id: params.agent_id,
        tool_id: params.tool_id,
        capability_class: capabilityClass,
        pas_score: pasScore,
      });
      const safeDecisions = new Set(['allow', 'deny', 'require_human_approval']);
      decision = safeDecisions.has(pd.decision)
        ? (pd.decision as typeof decision)
        : 'require_human_approval';
    }

    // 3. PAS check & update
    if (this.pasTracker && params.pas_updates) {
      const newScore = this.pasTracker.recordAction(params.agent_id, params.pas_updates);
      if (newScore.score > 100) {
        decision = 'require_human_approval';
      }
    }

    // 3. Create SAAE
    const action_id = `act_${crypto.randomUUID()}`;
    const baseEnvelope = createSAAEBase({
      action_id,
      timestamp: new Date().toISOString(),
      actor: {
        agent_id: params.agent_id,
        agent_cert_hash: hashObject(cert),
        signing_key_id: cert.signing_key_id,
      },
      authority: {
        org_id: cert.owner_org,
        delegation_hash: hashObject(params.delegation),
        intent_anchor_hash: hashObject(params.intent),
      },
      runtime: {
        runtime_cert_hash: params.runtime_cert_hash,
      },
      tool: {
        tool_id: params.tool_id,
        capability_class: capabilityClass,
        risk_level: riskLevel,
      },
      policy: {
        decision,
        risk_level: riskLevel,
        requires_human_approval: decision === 'require_human_approval',
      },
      action: {
        type: params.action_type,
        target_hash: hashObject({ tool_id: params.tool_id, action_type: params.action_type }),
        parameter_hash: hashObject(params.action_parameters),
      },
      evidence: {
        request_hash: hashObject({
          delegation: params.delegation,
          intent: params.intent,
          capability: params.capability,
          action_parameters: params.action_parameters,
        }),
        bundle_hash: hashObject({
          agent_id: params.agent_id,
          runtime_cert_hash: params.runtime_cert_hash,
          tool_id: params.tool_id,
          action_type: params.action_type,
        }),
      },
    });

    // 4. Sign SAAE
    // The agent signs a narrow action payload (not the full envelope).
    // The gateway countersigns the full unsigned envelope as a witness.

    // Verify agent signature against the agent_action subset
    const agentActionPayload = JSON.stringify({
      agent_id: params.agent_id,
      tool_id: params.tool_id,
      action_type: params.action_type,
      action_parameters: params.action_parameters,
      capability_id: params.capability.capability_id,
      timestamp: params.action_timestamp,
    });
    if (!verifySignature(agentActionPayload, params.agent_signature, cert.public_key)) {
      throw new Error('Invalid agent action signature');
    }

    // Gateway signs the full unsigned envelope as a witness
    const { signatures, ...unsignedPart } = baseEnvelope;
    const unsignedStr = JSON.stringify(unsignedPart);
    const gatewayWitnessSig = signData(unsignedStr, this.gatewayPrivateKey);

    // Runtime assertion: agent and gateway must use different keys
    if (cert.public_key === this.gatewayPrivateKey) {
      throw new Error('Agent public key must differ from gateway private key');
    }

    const finalEnvelope: SAAE = {
      ...baseEnvelope,
      signatures: {
        agent_action_signature: params.agent_signature,
        gateway_witness_signature: gatewayWitnessSig,
      },
    };

    // Append to action log if configured
    this.log?.append(finalEnvelope);

    return finalEnvelope;
  }

  private checkPolicy(cert: AgentCert, capability: CapabilityToken, tool_id: string) {
    if (capability.subject !== cert.agent_id) {
      throw new Error('Capability token subject mismatch');
    }
    if (capability.allowed_tool !== tool_id) {
      throw new Error(`Capability token does not allow tool: ${tool_id}`);
    }
    if (capability.constraints.expires_at && new Date(capability.constraints.expires_at) <= new Date()) {
      throw new Error('Capability token has expired');
    }
    if (capability.constraints.requires_human_approval) {
      // The policy decision is escalated by checkAuthority; this guard keeps the
      // lower-level token validation explicit.
      return;
    }
  }

  private checkAuthority(
    cert: AgentCert,
    delegation: DelegationGrant,
    intent: IntentAnchor,
    capability: CapabilityToken,
    request: { action_type: string; tool_id: string; capability_class: string },
  ) {
    if (delegation.agent_id !== cert.agent_id) {
      throw new Error('Delegation agent mismatch');
    }
    if (new Date(delegation.delegation.expires_at) <= new Date()) {
      throw new Error('Delegation has expired');
    }
    if (new Date(intent.expires_at) <= new Date()) {
      throw new Error('Intent has expired');
    }
    if (delegation.delegation.forbidden_actions.some(a => this.matchesScope(a, request))) {
      throw new Error(`Delegation forbids action: ${request.action_type}`);
    }
    if (intent.forbidden_actions.some(a => this.matchesScope(a, request))) {
      throw new Error(`Intent forbids action: ${request.action_type}`);
    }
    if (!delegation.delegation.allowed_actions.some(a => this.matchesScope(a, request))) {
      throw new Error(`Delegation does not allow action: ${request.action_type}`);
    }
    if (!intent.allowed_actions.some(a => this.matchesScope(a, request))) {
      throw new Error(`Intent does not allow action: ${request.action_type}`);
    }
    if (capability.constraints.requires_human_approval) {
      return;
    }
  }

  private matchesScope(scope: string, request: { action_type: string; tool_id: string; capability_class: string }) {
    return scope === request.action_type
      || scope === request.tool_id
      || scope === request.capability_class
      || scope === '*';
  }
}
