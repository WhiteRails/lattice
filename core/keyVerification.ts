import {
  CompromiseWindow,
  HistoricalSigStatus,
  KeyRecord,
  KeyStatus,
  RevocationRecord,
} from './types';

function ts(iso: string): number {
  return new Date(iso).getTime();
}

function withinCompromiseWindow(actionTime: number, w: CompromiseWindow): boolean {
  return actionTime >= ts(w.suspected_from) && actionTime <= ts(w.confirmed_at);
}

/**
 * Evaluates how a historical signature should be treated given key material
 * and revocation / compromise records (Trust Model §4.3).
 *
 * Callers must still verify the signature cryptographically against `public_key`
 * for `signingKeyId` at the time of the action.
 */
export function evaluateHistoricSigningKey(
  actionTimestampIso: string,
  signingKeyId: string,
  keys: KeyRecord[],
  revocations: RevocationRecord[],
): HistoricalSigStatus {
  const t = ts(actionTimestampIso);
  const key = keys.find(k => k.key_id === signingKeyId);
  if (!key) return 'invalid';

  const from = ts(key.valid_from);
  const until = key.valid_until !== undefined ? ts(key.valid_until) : Number.POSITIVE_INFINITY;
  if (t < from || t >= until) return 'invalid';

  const keyRevs = revocations.filter(
    r => r.target_key_id === signingKeyId && (r.target_type === 'SigningKey' || r.target_type === 'LatticeKey'),
  );

  for (const r of keyRevs) {
    if (r.reason_code === 'KEY_COMPROMISE' && r.compromise_window) {
      if (withinCompromiseWindow(t, r.compromise_window)) return 'valid_but_contested';
    }
  }

  if (key.status === 'REVOKED_COMPROMISED') {
    const cw = keyRevs.find(r => r.compromise_window)?.compromise_window;
    if (cw) {
      if (t < ts(cw.suspected_from)) return 'valid';
      if (withinCompromiseWindow(t, cw)) return 'valid_but_contested';
    }
    return 'requires_secondary_proof';
  }

  if (key.status === 'SUSPENDED') return 'invalid';

  // REVOKED_LOST: past signatures within declared validity may remain valid;
  // without loss_timestamp we treat as valid inside [valid_from, valid_until).
  if (key.status === 'REVOKED_LOST') {
    return 'valid';
  }

  if (key.status === 'ACTIVE' || key.status === 'DEPRECATED' || key.status === 'RETIRED') {
    return 'valid';
  }

  return 'invalid';
}
