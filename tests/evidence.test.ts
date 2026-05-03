import { describe, it, expect } from 'vitest';
import * as crypto from 'crypto';
import { EvidenceStore } from '../core/evidence';

function rsaPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  });
  return { publicKey, privateKey };
}

describe('EvidenceStore encryption key binding', () => {
  it('stores and re-encrypts with explicit encryption_key_id', async () => {
    const store = new EvidenceStore();
    const a = rsaPair();
    const b = rsaPair();
    const bundle = {
      action_id: 'act-ev-1',
      request: { x: 1 },
      response: { y: 2 },
      parameters: {},
      agent_id: 'agent-1',
      tool_id: 't1',
      timestamp: new Date().toISOString(),
    };

    const ev = await store.store_bundle(
      bundle,
      [{ id: 'party-a', publicKey: a.publicKey }],
      { encryption_key_id: 'ek_period_2026_q1', period_id: '2026-Q1' },
    );
    expect(ev.encryption_key_id).toBe('ek_period_2026_q1');
    expect(ev.period_id).toBe('2026-Q1');

    const re = await store.re_encrypt_bundle({
      ref: ev.ref,
      decrypt_as_recipient_id: 'party-a',
      recipient_private_key: a.privateKey,
      new_encryption_key_id: 'ek_period_2026_q2',
      new_period_id: '2026-Q2',
      new_recipients: [{ id: 'party-b', publicKey: b.publicKey }],
    });
    expect(re.encryption_key_id).toBe('ek_period_2026_q2');

    const out = await store.retrieve(re.ref, 'party-b', b.privateKey);
    expect(out.action_id).toBe('act-ev-1');

    store.markPotentiallyExposed(re.ref);
    expect(store.get(re.ref)?.exposure_status).toBe('POTENTIALLY_EXPOSED');
  });
});
