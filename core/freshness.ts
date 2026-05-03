import { RevocationFreshnessProof, RevocationFreshnessProofSchema } from './types';
import { RevocationNetwork } from './revocation';
import { hashData } from './envelope';
import { signData, verifySignature } from './identity';

const DEFAULT_MAX_STALENESS_MS = 5 * 60 * 1000; // 5 minutes

/**
 * RevocationFreshnessProver — signs a timestamped "not-revoked-as-of-T"
 * assertion for a certificate hash (§4.3).
 *
 * Used by Entry Nodes and Gateways before allowing high-risk actions.
 * The proof includes the max acceptable staleness so verifiers can enforce
 * their own freshness window.
 */
export class RevocationFreshnessProver {
  constructor(
    private readonly checkerId: string,
    private readonly checkerPrivateKey: string,
    private readonly revocationNetwork: RevocationNetwork,
    private readonly maxStalenessMs: number = DEFAULT_MAX_STALENESS_MS,
  ) {}

  /**
   * Checks if certHash is revoked and produces a signed freshness proof.
   */
  prove(certHash: string): RevocationFreshnessProof {
    const not_revoked = !this.revocationNetwork.isRevoked(certHash);
    const checked_at = new Date().toISOString();

    const unsigned = {
      schema: 'lattice.freshness.v0.1' as const,
      cert_hash: certHash,
      checked_at,
      not_revoked,
      checker_id: this.checkerId,
      max_staleness_ms: this.maxStalenessMs,
    };

    const signature = signData(JSON.stringify(unsigned), this.checkerPrivateKey);
    return RevocationFreshnessProofSchema.parse({ ...unsigned, signature });
  }
}

/**
 * RevocationFreshnessVerifier — verifies a freshness proof.
 *
 * Checks:
 * 1. Cryptographic signature is valid
 * 2. Proof is recent enough (within max_staleness_ms)
 * 3. The proof asserts not_revoked = true
 */
export class RevocationFreshnessVerifier {
  /**
   * Returns true if the proof is valid, fresh, and asserts not-revoked.
   */
  verify(
    proof: RevocationFreshnessProof,
    checkerPublicKey: string,
    acceptedStalenessMs: number = DEFAULT_MAX_STALENESS_MS,
  ): { valid: boolean; reason?: string } {
    // 1. Verify signature
    const { signature, ...unsigned } = proof;
    if (!verifySignature(JSON.stringify(unsigned), signature, checkerPublicKey)) {
      return { valid: false, reason: 'Invalid signature on freshness proof' };
    }

    // 2. Check staleness
    const age = Date.now() - new Date(proof.checked_at).getTime();
    const maxAge = Math.min(proof.max_staleness_ms, acceptedStalenessMs);
    if (age > maxAge) {
      return { valid: false, reason: `Freshness proof is stale (${age}ms > ${maxAge}ms)` };
    }

    // 3. Check not_revoked
    if (!proof.not_revoked) {
      return { valid: false, reason: 'Freshness proof confirms cert IS revoked' };
    }

    return { valid: true };
  }
}
