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

    const signaturePayload = toolCallSignaturePayload(params);
    if (!verifySignature(signaturePayload, params.agent_signature, cert.public_key)) {
      throw new Error('Invalid agent signature for tool call');
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

    // 3. Sign SAAE (In a real flow, the agent would sign this part)
    // For MVP, the gateway manages the process and signs as both a witness and validator
    const { signatures, ...unsignedPart } = baseEnvelope;
    const unsignedStr = JSON.stringify(unsignedPart);

    const finalEnvelope: SAAE = {
      ...baseEnvelope,
      signatures: {
        agent_signature: params.agent_signature,
        gateway_signature: signData(unsignedStr, this.gatewayPrivateKey),
      }
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
