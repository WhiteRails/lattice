import { describe, it, expect } from 'vitest';
import { LatticeCA } from '../core/ca';
import { RevocationNetwork } from '../core/revocation';
import { generateKeyPair } from '../core/identity';
import { hashObject } from '../core/envelope';

describe('LatticeCA', () => {
  it('issues and verifies an AgentCert', () => {
    const ca = new LatticeCA('ca.test');
    const { publicKey } = generateKeyPair();
    const signed = ca.issueAgentCert({
      agent_id: 'agent-test',
      owner_org: 'org-test',
      agent_type: 'worker',
      version: '1.0',
      public_key: publicKey,
      allowed_capability_classes: ['read:public'],
      forbidden_capability_classes: [],
      expires_in_days: 1,
    });

    expect(signed.cert.agent_id).toBe('agent-test');
    expect(signed.cert.type).toBe('AgentCert');
    expect(signed.ca_cert_id).toBe('ca.test');
    expect(ca.verifyCert(signed)).toBe(true);
  });

  it('issues OrgCert, ServiceCert, GatewayCert, RuntimeCert, ToolCert', () => {
    const ca = new LatticeCA('ca.test');
    expect(ca.issueOrgCert({ org_id: 'org-1' }).cert.type).toBe('OrgCert');
    expect(ca.issueServiceCert({ service_id: 'svc-1' }).cert.type).toBe('ServiceCert');
    expect(ca.issueGatewayCert({ gateway_id: 'gw-1' }).cert.type).toBe('GatewayCert');
    expect(ca.issueRuntimeCert({ runtime_id: 'rt-1' }).cert.type).toBe('RuntimeCert');
    expect(ca.issueToolCert({ tool_id: 'tool-1' }).cert.type).toBe('ToolCert');
  });

  it('revokes a cert and records it in the revocation network', () => {
    const ca = new LatticeCA('ca.test');
    const { publicKey } = generateKeyPair();
    const signed = ca.issueAgentCert({
      agent_id: 'agent-rev',
      owner_org: 'org',
      agent_type: 'bot',
      version: '1.0',
      public_key: publicKey,
      allowed_capability_classes: [],
      forbidden_capability_classes: [],
    });

    const rn = new RevocationNetwork();
    ca.revoke(signed.cert.id, 'test', rn);
    expect(rn.isRevoked(hashObject(signed.cert))).toBe(true);
  });

  it('signature fails if cert is tampered', () => {
    const ca = new LatticeCA('ca.test');
    const { publicKey } = generateKeyPair();
    const signed = ca.issueOrgCert({ org_id: 'org-1' });
    // Tamper
    const tampered = { ...signed, cert: { ...signed.cert, issuer: 'evil-ca' } };
    expect(ca.verifyCert(tampered)).toBe(false);
  });
});
