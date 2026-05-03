import { describe, it, expect, beforeEach } from 'vitest';
import { generateKeyPair, createAgentCert } from '../src/identity';
import { WhiteGateway } from '../src/gateway';
import { WhiteRegistry } from '../src/registry';
import { RevocationNetwork } from '../src/revocation';
import { PowerAccumulationTracker } from '../src/pas';
import { hashObject } from '../src/envelope';
import { DelegationGrant, IntentAnchor, CapabilityToken } from '../src/types';

describe('WhiteNet MVP Flow', () => {
  let gateway: WhiteGateway;
  let registry: WhiteRegistry;
  let revocation: RevocationNetwork;
  let pasTracker: PowerAccumulationTracker;
  let gatewayKeys: any;
  let agentKeys: any;
  let agentCert: any;

  beforeEach(() => {
    gatewayKeys = generateKeyPair();
    agentKeys = generateKeyPair();

    gateway = new WhiteGateway('gw-1', gatewayKeys.privateKey);
    registry = new WhiteRegistry();
    revocation = new RevocationNetwork();
    pasTracker = new PowerAccumulationTracker();

    gateway.setRevocationNetwork(revocation);
    gateway.setPASTracker(pasTracker);

    agentCert = createAgentCert({
      agent_id: 'agent-1',
      owner_org: 'org-1',
      agent_type: 'support',
      version: '1.0',
      public_key: agentKeys.publicKey,
      issuer: 'org-1-ca',
      allowed_capability_classes: ['email'],
      forbidden_capability_classes: [],
    });

    gateway.registerAgent(agentCert);
  });

  const mockDelegation: DelegationGrant = {
    human_subject: 'human-1',
    agent_id: 'agent-1',
    delegation: {
      allowed_actions: ['send'],
      forbidden_actions: [],
      expires_at: new Date(Date.now() + 100000).toISOString(),
    }
  };

  const mockIntent: IntentAnchor = {
    intent_id: 'intent-1',
    human_or_org: 'human-1',
    goal: 'reply to customer',
    allowed_actions: ['email:send'],
    forbidden_actions: [],
    expires_at: new Date(Date.now() + 100000).toISOString(),
  };

  const mockCapability: CapabilityToken = {
    capability_id: 'cap:email',
    subject: 'agent-1',
    delegated_by: 'human-1',
    allowed_tool: 'gmail.send',
    constraints: {
      requires_human_approval: false,
      expires_at: new Date(Date.now() + 100000).toISOString(),
    }
  };

  it('allows a valid tool call', async () => {
    const saae = await gateway.mediateToolCall({
      agent_id: 'agent-1',
      agent_signature: 'sig',
      delegation: mockDelegation,
      intent: mockIntent,
      capability: mockCapability,
      tool_id: 'gmail.send',
      action_type: 'send_email',
      action_parameters: { to: 'user@example.com', body: 'hello' },
      runtime_cert_hash: 'hash',
    });

    expect(saae.policy.decision).toBe('allow');
  });

  it('blocks a tool call if the agent certificate is revoked', async () => {
    revocation.publishRevocation({
      target_type: 'AgentCert',
      target_hash: hashObject(agentCert),
      revoked_by: 'org-1-ca',
      reason: 'security breach',
      issuerPrivateKey: gatewayKeys.privateKey, // Simplified for test
    });

    await expect(gateway.mediateToolCall({
      agent_id: 'agent-1',
      agent_signature: 'sig',
      delegation: mockDelegation,
      intent: mockIntent,
      capability: mockCapability,
      tool_id: 'gmail.send',
      action_type: 'send_email',
      action_parameters: {},
      runtime_cert_hash: 'hash',
    })).rejects.toThrow('Agent certificate for agent-1 has been revoked');
  });

  it('escalates to human approval if PAS exceeds threshold', async () => {
    const saae = await gateway.mediateToolCall({
      agent_id: 'agent-1',
      agent_signature: 'sig',
      delegation: mockDelegation,
      intent: mockIntent,
      capability: mockCapability,
      tool_id: 'gmail.send',
      action_type: 'send_email',
      action_parameters: {},
      runtime_cert_hash: 'hash',
      pas_updates: { agent_replication_attempted: 3 } // PAS will be 3 * 50 = 150 > 100
    });

    expect(saae.policy.decision).toBe('require_human_approval');
  });

  it('resolves WhiteNet addresses through registry', () => {
    const address = registry.register({
      certificate: agentCert,
      certificate_chain: [],
      accepted_capabilities: ['email'],
      protecting_gateways: ['gw-1'],
    });

    expect(address).toContain('.white');
    const record = registry.resolve(address);
    expect(record?.public_key).toBe(agentCert.public_key);
  });
});
