import { AgentCert, CapabilityToken, DelegationGrant, IntentAnchor, SAAE } from './types';
import { isCertValid, verifySignature, signData } from './identity';
import { createSAAEBase, hashObject, signSAAE } from './envelope';

export class WhiteGateway {
  private registeredAgents: Map<string, AgentCert> = new Map();

  constructor(public gatewayId: string, private gatewayPrivateKey: string) {}

  /**
   * Registers an agent certificate in the gateway.
   */
  registerAgent(cert: AgentCert) {
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
    tool_id: string;
    action_type: string;
    action_parameters: any;
    runtime_cert_hash: string;
  }): Promise<SAAE> {
    const cert = this.registeredAgents.get(params.agent_id);
    if (!cert) {
      throw new Error(`Agent ${params.agent_id} is not registered`);
    }

    // Verify agent's signature on the intent and action (simplified for MVP)
    // In a real protocol, the agent would sign the request payload
    // Here we assume the mediateToolCall itself is the request

    // 1. Policy & Capability check
    this.checkPolicy(cert, params.capability, params.tool_id);

    // 2. Create SAAE
    const action_id = `act_${crypto.randomUUID()}`;
    const baseEnvelope = createSAAEBase({
      action_id,
      timestamp: new Date().toISOString(),
      actor: {
        agent_id: params.agent_id,
        agent_cert_hash: hashObject(cert),
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
        capability_class: params.capability.capability_id.split(':')[1] || 'default',
      },
      policy: {
        decision: 'allow',
      },
      action: {
        type: params.action_type,
        target_hash: 'sha256:target', // Placeholder
        parameter_hash: hashObject(params.action_parameters),
      },
      evidence: {
        bundle_hash: 'sha256:evidence', // Placeholder
      },
    });

    // 3. Sign SAAE (In a real flow, the agent would sign this part)
    // For MVP, the gateway manages the process and signs as both a witness and validator
    const { signatures, ...unsignedPart } = baseEnvelope;
    const unsignedStr = JSON.stringify(unsignedPart);

    const finalEnvelope: SAAE = {
      ...baseEnvelope,
      signatures: {
        agent_signature: 'PENDING_AGENT_SIG', // In reality, this comes from the agent
        gateway_signature: signData(unsignedStr, this.gatewayPrivateKey),
      }
    };

    return finalEnvelope;
  }

  private checkPolicy(cert: AgentCert, capability: CapabilityToken, tool_id: string) {
    if (capability.subject !== cert.agent_id) {
      throw new Error('Capability token subject mismatch');
    }
    if (capability.allowed_tool !== tool_id) {
      throw new Error(`Capability token does not allow tool: ${tool_id}`);
    }
    // More complex policy checks would go here
  }
}
