/**
 * Example 3 — Signed trust manifest, Merkle transparency batch, and on-chain checkpoint hook.
 *
 * Run: npm run example:manifest
 */
import { generateKeyPair } from '../../core/identity';
import { LatticeLog } from '../../core/log';
import {
  appendManifestCommitEvent,
  manifestContentHash,
  signTrustManifest,
  verifyTrustManifestSignature,
} from '../../core/trust-manifest';
import { LatticeCA } from '../../core/ca';

function main() {
  const governanceKeys = generateKeyPair();
  const logKeys = generateKeyPair();
  const log = new LatticeLog('transparency.lattice.global', logKeys.privateKey);

  const govUx = new LatticeCA('gov:ux:identity-ca');
  const govAr = new LatticeCA('gov:ar:identity-ca');

  const manifest = {
    schema: 'lattice.trust-manifest.v0.1' as const,
    manifest_id: 'manifest-gov-registry-2026-05',
    issued_at: new Date().toISOString(),
    issuers: [
      {
        issuer_id: govUx.id,
        public_key: govUx.publicKey,
        allowed_cert_types: ['AgentCert', 'OrgCert'],
      },
      {
        issuer_id: govAr.id,
        public_key: govAr.publicKey,
        allowed_cert_types: ['AgentCert'],
      },
    ],
  };

  const signed = signTrustManifest(manifest, 'governance-root-2026', governanceKeys.privateKey);

  if (!verifyTrustManifestSignature(signed, governanceKeys.publicKey)) {
    throw new Error('governance signature verification failed');
  }

  const contentHash = manifestContentHash(signed);
  console.log('--- Signed manifest (canonical bytes hashed for transparency) ---');
  console.log(`manifest_id: ${signed.manifest.manifest_id}`);
  console.log(`manifest_content_hash (sha256 of stable JSON): ${contentHash}`);
  console.log(`governance signer_id: ${signed.signer_id}`);

  appendManifestCommitEvent(log, signed, 'org:lattice:federation-log', ['key_log_operator_1']);

  const batch = log.computeBatch();
  console.log('\n--- Merkle batch (transparency log seal) ---');
  console.log(`batch_id: ${batch.batch_id}`);
  console.log(`merkle_root: ${batch.merkle_root}`);
  console.log(`log operator signature on batch metadata: ${batch.signature.slice(0, 48)}…`);

  const proof = log.getProofByEntryIndex(0);
  if (!proof || !log.verifyProof(proof)) {
    throw new Error('Merkle inclusion proof for manifest commit should verify');
  }
  console.log('\n--- Merkle inclusion proof for log entry 0 ---');
  console.log(`leaf binds to batch root: ${log.verifyProof(proof)}`);

  console.log('\n--- On-chain checkpoint (LatticeChain) ---');
  console.log(
    'Use node/chain.ts submitCheckpoint() with this batch JSON (see ~/.lattice/batches/ in full CLI flow), e.g.:',
  );
  console.log(
    JSON.stringify(
      {
        batch_id: batch.batch_id,
        merkle_root: `0x${batch.merkle_root}`,
        from_timestamp: log.getEntries()[0]?.timestamp,
        to_timestamp: log.getEntries()[log.getEntries().length - 1]?.timestamp,
        action_count: batch.action_count,
      },
      null,
      2,
    ),
  );
  console.log(
    '\nVerifiers: (1) verify governance signature on stableStringify(manifest), (2) hash manifest → compare to event.manifest_content_hash, (3) verify Merkle proof to batch root, (4) compare batch root to chain via verifyCheckpointOnChain().',
  );

  // Tamper: same signature no longer verifies
  const tampered = { ...signed, manifest: { ...signed.manifest, manifest_id: 'evil-swap' } };
  if (verifyTrustManifestSignature(tampered, governanceKeys.publicKey)) {
    throw new Error('tampered manifest should not verify');
  }
  console.log('\nTampered manifest (changed manifest_id): governance signature correctly fails.');
}

main();
