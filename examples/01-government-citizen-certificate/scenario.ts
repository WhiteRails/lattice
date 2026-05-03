/**
 * Example 1 — Government-issued citizen credential (trust registry simulation).
 *
 * Run: npm run example:gov
 */
import { LatticeCA, SignedCert } from '../../core/ca';
import { AgentCert, WhiteCertificate } from '../../core/types';
import { generateKeyPair, verifySignature } from '../../core/identity';

/** Simulates LatticeChain IssuerRegistry: issuer_id -> trusted CA public key (Ed25519 PEM). */
const TRUSTED_GOVERNMENT_ISSUERS = new Map<string, string>();

function registerTrustedGovernmentIssuer(ca: LatticeCA) {
  TRUSTED_GOVERNMENT_ISSUERS.set(ca.id, ca.publicKey);
}

/**
 * Verifier-side: only issuers listed in TRUSTED_GOVERNMENT_ISSUERS may issue,
 * and the signature MUST verify with THAT registry key (not self-asserted).
 */
function verifyGovernmentIssuedAgentCert(signed: SignedCert<AgentCert>): { ok: true } | { ok: false; reason: string } {
  const issuerId = signed.cert.issuer;
  const registeredPk = TRUSTED_GOVERNMENT_ISSUERS.get(issuerId);
  if (!registeredPk) {
    return { ok: false, reason: `Issuer "${issuerId}" is not in the government trust registry` };
  }
  const payload = JSON.stringify(signed.cert);
  if (!verifySignature(payload, signed.ca_signature, registeredPk)) {
    return {
      ok: false,
      reason:
        'Signature does not match the registered public key for this issuer (impersonation or wrong key)',
    };
  }
  return { ok: true };
}

function main() {
  const legitimateGov = new LatticeCA('gov:ux:identity-ca');
  registerTrustedGovernmentIssuer(legitimateGov);

  const citizenKeys = generateKeyPair();
  const elonMuskDemoCert = legitimateGov.issueAgentCert({
    agent_id: 'agent:citizen:elon-musk-demo',
    owner_org: 'org:government:national-registry',
    agent_type: 'human_identity_bound',
    version: '1.0',
    public_key: citizenKeys.publicKey,
    allowed_capability_classes: ['identity:prove', 'read:private'],
    forbidden_capability_classes: ['money:execute', 'code:deploy'],
    expires_in_days: 365,
  });

  console.log('--- Legitimate issuance ---');
  console.log(`Issuer: ${elonMuskDemoCert.cert.issuer}`);
  console.log(`Subject agent_id: ${elonMuskDemoCert.cert.agent_id}`);
  const good = verifyGovernmentIssuedAgentCert(elonMuskDemoCert);
  console.log(good.ok ? 'VERIFY: accepted' : `VERIFY: rejected — ${good.reason}`);

  // Attacker CA: not registered — cannot pass as government even if they mint a cert object.
  const scammerCa = new LatticeCA('gov:totally-legit.fake');
  const fakeCert = scammerCa.issueAgentCert({
    agent_id: 'agent:citizen:elon-musk-demo',
    owner_org: 'org:government:national-registry',
    agent_type: 'human_identity_bound',
    version: '1.0',
    public_key: citizenKeys.publicKey,
    allowed_capability_classes: ['identity:prove'],
    forbidden_capability_classes: [],
    expires_in_days: 365,
  });

  console.log('\n--- Unregistered "government" CA ---');
  console.log(`Issuer: ${fakeCert.cert.issuer}`);
  const badRegistry = verifyGovernmentIssuedAgentCert(fakeCert);
  console.log(badRegistry.ok ? 'VERIFY: accepted' : `VERIFY: rejected — ${badRegistry.reason}`);

  // Attacker reuses the SAME issuer_id string but is not the registered keypair.
  const impersonator = LatticeCA.fromKeyPair('gov:ux:identity-ca', generateKeyPair());
  const impersonationCert = impersonator.issueAgentCert({
    agent_id: 'agent:citizen:victim',
    owner_org: 'org:government:national-registry',
    agent_type: 'human_identity_bound',
    version: '1.0',
    public_key: generateKeyPair().publicKey,
    allowed_capability_classes: ['identity:prove'],
    forbidden_capability_classes: [],
    expires_in_days: 1,
  });

  console.log('\n--- Same issuer_id, wrong keys (not the registered gov key) ---');
  const badSig = verifyGovernmentIssuedAgentCert(impersonationCert);
  console.log(badSig.ok ? 'VERIFY: accepted' : `VERIFY: rejected — ${badSig.reason}`);

  // Sanity: direct verify on the legitimate CA instance
  if (!legitimateGov.verifyCert(elonMuskDemoCert as SignedCert<WhiteCertificate>)) {
    throw new Error('LatticeCA.verifyCert should accept its own issuance');
  }
}

main();
