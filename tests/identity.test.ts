import { describe, it, expect } from 'vitest';
import { generateKeyPair, createAgentCert, isCertValid, signData, verifySignature } from '../core/identity';

describe('Identity Layer', () => {
  it('should generate a valid key pair', () => {
    const keyPair = generateKeyPair();
    expect(keyPair.publicKey).toContain('BEGIN PUBLIC KEY');
    expect(keyPair.privateKey).toContain('BEGIN PRIVATE KEY');
  });

  it('should create and validate an AgentCert', () => {
    const keyPair = generateKeyPair();
    const cert = createAgentCert({
      agent_id: 'agent:test',
      owner_org: 'org:test',
      agent_type: 'test-agent',
      version: '1.0.0',
      public_key: keyPair.publicKey,
      issuer: 'ca:test',
      allowed_capability_classes: ['read:public'],
      forbidden_capability_classes: ['write:external'],
      expires_in_days: 1,
    });

    expect(cert.agent_id).toBe('agent:test');
    expect(isCertValid(cert)).toBe(true);
  });

  it('should sign and verify data', () => {
    const keyPair = generateKeyPair();
    const data = 'hello world';
    const signature = signData(data, keyPair.privateKey);
    const isValid = verifySignature(data, signature, keyPair.publicKey);
    expect(isValid).toBe(true);
  });
});
