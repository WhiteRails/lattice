import { describe, it, expect } from 'vitest';
import { generateKeyPair } from '../core/identity';
import { LatticeLog } from '../core/log';
import {
  appendManifestCommitEvent,
  manifestContentHash,
  signTrustManifest,
  verifyTrustManifestSignature,
} from '../core/trust-manifest';
import { LatticeCA } from '../core/ca';

describe('trust manifest + transparency', () => {
  it('signs, commits to log, seals batch, and Merkle-proves entry 0', () => {
    const govKeys = generateKeyPair();
    const logKeys = generateKeyPair();
    const log = new LatticeLog('test-manifest-log', logKeys.privateKey);
    const ca = new LatticeCA('gov:zz:test');

    const manifest = {
      schema: 'lattice.trust-manifest.v0.1' as const,
      manifest_id: 'm1',
      issued_at: new Date().toISOString(),
      issuers: [{ issuer_id: ca.id, public_key: ca.publicKey, allowed_cert_types: ['AgentCert'] }],
    };
    const signed = signTrustManifest(manifest, 'gov-root', govKeys.privateKey);
    expect(verifyTrustManifestSignature(signed, govKeys.publicKey)).toBe(true);

    appendManifestCommitEvent(log, signed, 'issuer:federation', ['k1']);
    const batch = log.computeBatch();
    expect(batch.action_count).toBe(1);

    const proof = log.getProofByEntryIndex(0);
    expect(proof).toBeDefined();
    expect(log.verifyProof(proof!)).toBe(true);
    expect(proof!.root).toBe(batch.merkle_root);
  });

  it('content hash changes when manifest body changes', () => {
    const keys = generateKeyPair();
    const ca = new LatticeCA('gov:zz:test');
    const m1 = signTrustManifest(
      {
        schema: 'lattice.trust-manifest.v0.1',
        manifest_id: 'a',
        issued_at: '2026-05-03T12:00:00.000Z',
        issuers: [{ issuer_id: ca.id, public_key: ca.publicKey, allowed_cert_types: ['AgentCert'] }],
      },
      's',
      keys.privateKey,
    );
    const m2 = signTrustManifest(
      {
        schema: 'lattice.trust-manifest.v0.1',
        manifest_id: 'b',
        issued_at: '2026-05-03T12:00:00.000Z',
        issuers: [{ issuer_id: ca.id, public_key: ca.publicKey, allowed_cert_types: ['AgentCert'] }],
      },
      's',
      keys.privateKey,
    );
    expect(manifestContentHash(m1)).not.toBe(manifestContentHash(m2));
  });
});
