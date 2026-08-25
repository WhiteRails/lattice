import { describe, expect, it } from 'vitest';
import { LatticeCA } from '../core/ca';
import { generateKeyPair } from '../core/identity';
import { verifyTrustedAgentIssuer } from '../core/issuer-trust';

describe('issuer-backed agent trust', () => {
  it('accepts only a current certificate bound to the configured issuer, subject, and agent key', () => {
    const issuer = new LatticeCA('issuer.example');
    const agent = generateKeyPair();
    const signed = issuer.issueAgentCert({
      agent_id: 'agent:acme:bot1', owner_org: 'acme', agent_type: 'autonomous', version: '1', public_key: agent.publicKey,
      allowed_capability_classes: [], forbidden_capability_classes: [], expires_in_days: 1,
    });
    const trust = { issuer_id: issuer.id, public_key: issuer.publicKey, subject: 'agent:acme:bot1' };
    expect(verifyTrustedAgentIssuer(signed, trust, agent.publicKey)).toBe(true);
    expect(verifyTrustedAgentIssuer(signed, { ...trust, subject: 'agent:acme:other' }, agent.publicKey)).toBe(false);
    expect(verifyTrustedAgentIssuer(signed, trust, generateKeyPair().publicKey)).toBe(false);
    expect(verifyTrustedAgentIssuer({ ...signed, ca_signature: 'forged' }, trust, agent.publicKey)).toBe(false);
  });
});
