import { describe, expect, it } from 'vitest';
import {
  CRED_ENTERPRISE,
  CRED_GOVERNMENT,
  CRED_MODEL,
  clientMeetsNamespacePolicy,
  credentialMaskFromNames,
} from '../core/namespace-access';

describe('credentialMaskFromNames', () => {
  it('ORs bits', () => {
    expect(credentialMaskFromNames(['gov', 'model'])).toBe(CRED_GOVERNMENT | CRED_MODEL);
    expect(credentialMaskFromNames(['enterprise'])).toBe(CRED_ENTERPRISE);
    expect(credentialMaskFromNames(['gov', 'enterprise', 'model'])).toBe(7);
  });
  it('rejects unknown', () => {
    expect(() => credentialMaskFromNames(['nope'])).toThrow(/Unknown credential/);
  });
});

describe('clientMeetsNamespacePolicy', () => {
  it('allows when public', () => {
    expect(
      clientMeetsNamespacePolicy(
        { publicAccess: true, credentialMask: 0, minAssuranceLevel: 99 },
        0,
        0,
      ),
    ).toEqual({ ok: true });
  });

  it('denies when not public and mask 0', () => {
    const r = clientMeetsNamespacePolicy(
      { publicAccess: false, credentialMask: 0, minAssuranceLevel: 0 },
      CRED_GOVERNMENT,
      5,
    );
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.reason).toMatch(/credentialMask is 0/);
  });

  it('requires OR bit match', () => {
    expect(
      clientMeetsNamespacePolicy(
        { publicAccess: false, credentialMask: CRED_GOVERNMENT | CRED_MODEL, minAssuranceLevel: 0 },
        CRED_ENTERPRISE,
        0,
      ).ok,
    ).toBe(false);
    expect(
      clientMeetsNamespacePolicy(
        { publicAccess: false, credentialMask: CRED_GOVERNMENT | CRED_MODEL, minAssuranceLevel: 0 },
        CRED_MODEL,
        0,
      ),
    ).toEqual({ ok: true });
  });

  it('enforces minAssuranceLevel', () => {
    const r = clientMeetsNamespacePolicy(
      { publicAccess: false, credentialMask: CRED_GOVERNMENT, minAssuranceLevel: 3 },
      CRED_GOVERNMENT,
      2,
    );
    expect(r.ok).toBe(false);
  });
});
