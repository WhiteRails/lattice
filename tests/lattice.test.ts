import { describe, it, expect, beforeEach } from 'vitest';
import { generateKeyPair, createAgentCert, signData } from '../core/identity';
import { LatticeGateway } from '../core/gateway';
import { LatticeRegistry } from '../core/registry';
import { RevocationNetwork } from '../core/revocation';
import { PowerAccumulationTracker } from '../core/pas';
import { LatticeLog } from '../core/log';
import { hashObject } from '../core/envelope';
import { DelegationGrant, IntentAnchor, CapabilityToken } from '../core/types';
import { LatticeCA } from '../core/ca';

describe('Lattice MVP Flow', () => {
  let gateway: LatticeGateway;
  let registry: LatticeRegistry;
  let revocation: RevocationNetwork;
  let pasTracker: PowerAccumulationTracker;
  let log: LatticeLog;
  let gatewayKeys: ReturnType<typeof generateKeyPair>;
  let agentKeys: ReturnType<typeof generateKeyPair>;
  let agentCert: ReturnType<typeof createAgentCert>;
  let ca: LatticeCA;

  beforeEach(() => {
    gatewayKeys = generateKeyPair();
    agentKeys = generateKeyPair();
    ca = new LatticeCA('org-1-ca');

    const logKeys = generateKeyPair();
    log = new LatticeLog('test-log', logKeys.privateKey);

    gateway = new LatticeGateway('gw-1', gatewayKeys.privateKey);
    registry = new LatticeRegistry('test-registry', log);
    revocation = new RevocationNetwork();
    pasTracker = new PowerAccumulationTracker();

    gateway.setRevocationNetwork(revocation);
    gateway.setPASTracker(pasTracker);
    gateway.setRegistry(registry);

    const signedAgentCert = ca.issueAgentCert({
      agent_id: 'agent-1',
      owner_org: 'org-1',
      agent_type: 'support',
      version: '1.0',
      public_key: agentKeys.publicKey,
      issuer: 'org-1-ca',
      allowed_capability_classes: ['email'],
      forbidden_capability_classes: [],
    });
    agentCert = signedAgentCert.cert;

    gateway.registerAgent(signedAgentCert, ca.publicKey);
  });

  const mockDelegation: DelegationGrant = {
    human_subject: 'human-1',
    agent_id: 'agent-1',
    delegation: {
      allowed_actions: ['email:send', 'message:mass'],
      forbidden_actions: [],
      expires_at: new Date(Date.now() + 100000).toISOString(),
    },
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
    },
  };

  it('allows a valid tool call', async () => {
    const request = {
      agent_id: 'agent-1',
      delegation: mockDelegation,
      intent: mockIntent,
      capability: mockCapability,
      capability_class: 'email:send',
      tool_id: 'gmail.send',
      action_type: 'email:send',
      action_parameters: { to: 'user@example.com', body: 'hello' },
      runtime_cert_hash: 'hash',
    };

    const actionTimestamp = new Date().toISOString();
    const agentActionPayload = JSON.stringify({
      agent_id: request.agent_id,
      tool_id: request.tool_id,
      action_type: request.action_type,
      action_parameters: request.action_parameters,
      capability_id: mockCapability.capability_id,
      timestamp: actionTimestamp,
    });

    const saae = await gateway.mediateToolCall({
      ...request,
      action_timestamp: actionTimestamp,
      agent_signature: signData(agentActionPayload, agentKeys.privateKey),
    });

    expect(saae.policy.decision).toBe('allow');
    expect(saae.actor.signing_key_id).toBe('key_initial_signing');
  });

  it('blocks a tool call if the agent certificate is revoked', async () => {
    revocation.publishRevocation({
      target_type: 'AgentCert',
      target_hash: hashObject(agentCert),
      revoked_by: 'org-1-ca',
      reason: 'security breach',
      issuerPrivateKey: gatewayKeys.privateKey,
    });

    await expect(
      (() => {
        const request = {
          agent_id: 'agent-1',
          delegation: mockDelegation,
          intent: mockIntent,
          capability: mockCapability,
          capability_class: 'email:send',
          tool_id: 'gmail.send',
          action_type: 'email:send',
          action_parameters: {},
          runtime_cert_hash: 'hash',
        };
        const ts = new Date().toISOString();
        return gateway.mediateToolCall({
          ...request,
          action_timestamp: ts,
          agent_signature: signData(JSON.stringify({ agent_id: request.agent_id, tool_id: request.tool_id, action_type: request.action_type, action_parameters: request.action_parameters, capability_id: mockCapability.capability_id, timestamp: ts }), agentKeys.privateKey),
        });
      })(),
    ).rejects.toThrow('Agent certificate for agent-1 has been revoked');
  });

  it('escalates to human approval if PAS exceeds threshold', async () => {
    const request = {
        agent_id: 'agent-1',
        delegation: mockDelegation,
        intent: mockIntent,
        capability: mockCapability,
        capability_class: 'email:send',
        tool_id: 'gmail.send',
        action_type: 'email:send',
        action_parameters: {},
        runtime_cert_hash: 'hash',
        pas_updates: { agent_replication_attempted: 3 },
      };
    const actionTimestamp = new Date().toISOString();
    const agentActionPayload = JSON.stringify({
      agent_id: request.agent_id,
      tool_id: request.tool_id,
      action_type: request.action_type,
      action_parameters: request.action_parameters,
      capability_id: mockCapability.capability_id,
      timestamp: actionTimestamp,
    });
    const saae = await gateway.mediateToolCall({
      ...request,
      action_timestamp: actionTimestamp,
      agent_signature: signData(agentActionPayload, agentKeys.privateKey),
    });

    expect(saae.policy.decision).toBe('require_human_approval');
  });

  it('resolves Lattice names through registry with stable subject', () => {
    const name = registry.register({
      name: 'agent-1.test.lattice',
      subject_id: 'did:traceveil:org:org-1',
      public_key: agentCert.public_key,
      signing_key_id: 'key_initial_signing',
      service_cert: agentCert.id,
      gateway_endpoints: ['quic://gw-1:4433'],
      issuer: 'org-1-ca',
      accepted_agent_issuers: ['org-1-ca'],
      linked_org_id: 'org-1',
    });

    expect(name).toBe('agent-1.test.lattice');
    const record = registry.resolve(name);
    expect(record?.subject_id).toBe('did:traceveil:org:org-1');
    expect(record?.keys[0].key_id).toBe('key_initial_signing');
    expect(registry.getPublicKey(name)).toBe(agentCert.public_key);
  });

  it('blocks high-risk tool calls when org subject is frozen', async () => {
    registry.register({
      name: 'agent-1.test.lattice',
      subject_id: 'did:traceveil:org:org-1',
      public_key: agentCert.public_key,
      service_cert: agentCert.id,
      gateway_endpoints: ['quic://gw-1:4433'],
      issuer: 'org-1-ca',
      accepted_agent_issuers: ['org-1-ca'],
      linked_org_id: 'org-1',
    });

    registry.freezeSubject({
      name: 'agent-1.test.lattice',
      reason: 'suspected_key_compromise',
      effect: {
        block_new_cert_issuance: true,
        block_high_risk_actions: true,
        allow_read_only_verification: true,
      },
      signed_by: ['recovery_key_1', 'recovery_key_2'],
      effective_at: new Date().toISOString(),
    });

    const massCap: CapabilityToken = {
      ...mockCapability,
      capability_id: 'cap:message:mass',
      allowed_tool: 'mailing.broadcast',
    };

    await expect(
      (() => {
        const request = {
          agent_id: 'agent-1',
          delegation: mockDelegation,
          intent: mockIntent,
          capability: massCap,
          capability_class: 'message:mass',
          tool_id: 'mailing.broadcast',
          action_type: 'message:mass',
          action_parameters: {},
          runtime_cert_hash: 'hash',
        };
        const ts = new Date().toISOString();
        return gateway.mediateToolCall({
          ...request,
          action_timestamp: ts,
          agent_signature: signData(JSON.stringify({ agent_id: request.agent_id, tool_id: request.tool_id, action_type: request.action_type, action_parameters: request.action_parameters, capability_id: massCap.capability_id, timestamp: ts }), agentKeys.privateKey),
        });
      })(),
    ).rejects.toThrow('Subject frozen');
  });
});
