/**
 * Namespace DNS-level access policy (mirrors LatticeChain.sol CRED_* bits).
 * Gateways / entry nodes should call `clientMeetsNamespacePolicy` before forwarding.
 */

export const CRED_GOVERNMENT = 1;
export const CRED_ENTERPRISE = 2;
export const CRED_MODEL = 4;

export const CRED_NAMES: Record<string, number> = {
  gov: CRED_GOVERNMENT,
  government: CRED_GOVERNMENT,
  enterprise: CRED_ENTERPRISE,
  ent: CRED_ENTERPRISE,
  model: CRED_MODEL,
  provider: CRED_MODEL,
};

/** OR together named credential classes, e.g. `['gov', 'enterprise']` → 3 */
export function credentialMaskFromNames(names: string[]): number {
  let m = 0;
  for (const raw of names) {
    const k = raw.trim().toLowerCase();
    const bit = CRED_NAMES[k];
    if (bit === undefined) throw new Error(`Unknown credential class: ${raw} (use gov|enterprise|model)`);
    m |= bit;
  }
  return m;
}

export interface NamespaceGatePolicy {
  publicAccess: boolean;
  credentialMask: number;
  minAssuranceLevel: number;
}

/**
 * If publicAccess → allow. Else require at least one credential class bit in mask
 * to match `clientCredentialMask` (OR semantics). Empty client mask fails when policy mask non-zero.
 */
export function clientMeetsNamespacePolicy(
  policy: NamespaceGatePolicy,
  clientCredentialMask: number,
  clientAssuranceLevel: number,
): { ok: true } | { ok: false; reason: string } {
  if (policy.publicAccess) return { ok: true };
  if (policy.credentialMask === 0) {
    return { ok: false, reason: 'Namespace is not public and credentialMask is 0 (deny all)' };
  }
  if ((clientCredentialMask & policy.credentialMask) === 0) {
    return { ok: false, reason: 'Client credential class not accepted for this namespace' };
  }
  if (clientAssuranceLevel < policy.minAssuranceLevel) {
    return {
      ok: false,
      reason: `Client assurance ${clientAssuranceLevel} < required ${policy.minAssuranceLevel}`,
    };
  }
  return { ok: true };
}
