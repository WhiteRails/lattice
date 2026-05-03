import { describe, it, expect, beforeEach } from 'vitest';
import { generateKeyPair } from '../core/identity';
import { LatticeRegistry } from '../core/registry';
import { RevocationNetwork } from '../core/revocation';
import { LatticeLog } from '../core/log';
import { evaluateHistoricSigningKey } from '../core/keyVerification';

describe('Key lifecycle & historic verification', () => {
  let log: LatticeLog;
  let registry: LatticeRegistry;
  let revocation: RevocationNetwork;

  beforeEach(() => {
    const logKeys = generateKeyPair();
    log = new LatticeLog('lifecycle-log', logKeys.privateKey);
    registry = new LatticeRegistry('lifecycle-reg', log);
    revocation = new RevocationNetwork();
  });

  it('rotates signing key with overlap window', () => {
    const k1 = generateKeyPair();
    const k2 = generateKeyPair();
    registry.register({
      name: 'svc.example.lattice',
      subject_id: 'did:traceveil:org:example',
      public_key: k1.publicKey,
      signing_key_id: 'key_2026_q1',
      service_cert: 'cert:svc',
      gateway_endpoints: [],
      issuer: 'ca:example',
      accepted_agent_issuers: [],
    });

    const t0 = '2026-06-01T00:00:00.000Z';
    const t1 = '2026-06-15T00:00:00.000Z';
    registry.rotateSigningKey({
      name: 'svc.example.lattice',
      old_key_id: 'key_2026_q1',
      new_key_id: 'key_2026_q2',
      new_public_key: k2.publicKey,
      effective_at: t0,
      old_key_valid_until: t1,
      signed_by: ['key_2026_q1', 'recovery_key'],
    });

    const rec = registry.resolve('svc.example.lattice')!;
    expect(rec.keys.filter(k => k.key_id === 'key_2026_q1')[0].status).toBe('DEPRECATED');
    expect(rec.keys.filter(k => k.key_id === 'key_2026_q2')[0].status).toBe('ACTIVE');
  });

  it('marks compromise window and evaluates historic signing status', () => {
    const k1 = generateKeyPair();
    const k2 = generateKeyPair();
    const now = Date.now();
    const suspected_from = new Date(now - 120_000).toISOString();
    const confirmed_at = new Date(now + 120_000).toISOString();
    const inside_window = new Date(now - 60_000).toISOString();
    const before_window = new Date(now - 300_000).toISOString();

    registry.register({
      name: 'org.clipma.lattice',
      subject_id: 'did:traceveil:org:clipma',
      public_key: k1.publicKey,
      signing_key_id: 'key_2026_q1',
      valid_from: new Date(now - 600_000).toISOString(),
      service_cert: 'cert:org',
      gateway_endpoints: [],
      issuer: 'ca:root',
      accepted_agent_issuers: [],
    });

    const cw = { suspected_from, confirmed_at };
    registry.emergencyKeyCompromise({
      name: 'org.clipma.lattice',
      compromised_key_id: 'key_2026_q1',
      compromise_window: cw,
      new_key_id: 'key_2026_emergency',
      new_public_key: k2.publicKey,
      requires_reaudit: true,
      signed_by: ['recovery_key_1', 'recovery_key_2'],
      threshold: '2-of-3',
      effective_at: new Date(now + 180_000).toISOString(),
    });

    revocation.publishRevocation({
      target_type: 'SigningKey',
      target_hash: 'did:traceveil:org:clipma#key_2026_q1',
      revoked_by: 'recovery',
      reason: 'compromise',
      issuerPrivateKey: k2.privateKey,
      target_key_id: 'key_2026_q1',
      reason_code: 'KEY_COMPROMISE',
      compromise_window: cw,
    });

    const keys = registry.resolve('org.clipma.lattice')!.keys;
    const revs = revocation.listRevocations();

    expect(evaluateHistoricSigningKey(inside_window, 'key_2026_q1', keys, revs)).toBe('valid_but_contested');
    expect(evaluateHistoricSigningKey(before_window, 'key_2026_q1', keys, revs)).toBe('valid');
  });
});
