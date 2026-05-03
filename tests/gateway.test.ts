import { describe, it, expect } from 'vitest';
import { LatticeGateway } from '../core/gateway';
import { generateKeyPair, createAgentCert } from '../core/identity';
import { DelegationGrant, IntentAnchor, CapabilityToken } from '../core/types';

describe('Lattice Gateway', () => {
  it('should mediate a tool call and produce a signed SAAE', async () => {
    const gatewayKeyPair = generateKeyPair();
    const gateway = new LatticeGateway('gateway:test', gatewayKeyPair.privateKey);

    const agentKeyPair = generateKeyPair();
    const agentCert = createAgentCert({
      agent_id: 'agent:test',
      owner_org: 'org:test',
      agent_type: 'test-agent',
      version: '1.0.0',
      public_key: agentKeyPair.publicKey,
      issuer: 'ca:test',
      allowed_capability_classes: ['email:draft'],
      forbidden_capability_classes: [],
    });

    gateway.registerAgent(agentCert);

    const delegation: DelegationGrant = {
      human_subject: 'user:test',
      agent_id: 'agent:test',
      delegation: {
        allowed_actions: ['email:draft'],
        forbidden_actions: [],
        expires_at: new Date(Date.now() + 86400000).toISOString(),
      },
    };

    const intent: IntentAnchor = {
      intent_id: 'intent:test',
      human_or_org: 'user:test',
      goal: 'test mediation',
      allowed_actions: ['email:draft'],
      forbidden_actions: [],
      expires_at: new Date(Date.now() + 3600000).toISOString(),
    };

    const capability: CapabilityToken = {
      capability_id: 'cap:email:draft',
      subject: 'agent:test',
      delegated_by: 'org:test',
      allowed_tool: 'tool:gmail.draft',
      constraints: {
        requires_human_approval: false,
        expires_at: new Date(Date.now() + 3600000).toISOString(),
      },
    };

    const envelope = await gateway.mediateToolCall({
      agent_id: 'agent:test',
      agent_signature: 'AGENT_SIG',
      delegation,
      intent,
      capability,
      tool_id: 'tool:gmail.draft',
      action_type: 'gmail.draft_email',
      action_parameters: { to: 'test@example.com' },
      runtime_cert_hash: 'sha256:runtime',
    });

    expect(envelope.actor.agent_id).toBe('agent:test');
    expect(envelope.signatures.gateway_signature).toBeDefined();
    expect(envelope.signatures.gateway_signature).not.toBe('GATEWAY_SIGNATURE_PLACEHOLDER');
  });

  it('should throw if agent is not registered', async () => {
     const gatewayKeyPair = generateKeyPair();
     const gateway = new LatticeGateway('gateway:test', gatewayKeyPair.privateKey);

     await expect(gateway.mediateToolCall({
       agent_id: 'agent:unregistered',
       // ... other params don't matter much for this test
     } as any)).rejects.toThrow('Agent agent:unregistered is not registered');
  });
});
