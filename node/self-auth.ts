/**
 * Self-authenticating lp:// addresses for Lattice nodes.
 *
 * Format: lp://<hex64(raw_pubkey_bytes)>.id
 *
 * The address IS the identity:
 *  - No chain lookup required — pubkey is embedded in the address.
 *  - When connecting, verify that the endpoint's source_pubkey matches
 *    the pubkey extracted from the .id address.
 *  - *.lattice names are human aliases; *.id addresses are the canonical identity.
 *
 * Comparison to Tor onion v3:
 *  - Tor:    base32(sha3(ed25519_pubkey)) — one-way hash (pubkey separate)
 *  - Lattice .id: hex(x25519_pubkey)     — inline pubkey (no separate lookup)
 *
 * Trade-off: hex inline is slightly longer (64 chars vs 52) but allows direct
 * verification without a DHT lookup for the pubkey.
 */

/** `.id` TLD used for self-authenticating addresses. */
export const SELF_AUTH_TLD = '.id';

/**
 * Derive the self-authenticating lp:// address from a base64-encoded X25519 pubkey.
 * Returns fqdn like `deadbeef...cafebabe.id` (64 hex chars + ".id").
 */
export function deriveSelfAuthAddress(pubkeyB64: string): string {
  const raw = Buffer.from(pubkeyB64.trim(), 'base64');
  if (raw.length === 0) throw new Error('Invalid pubkey: empty bytes');
  return `${raw.toString('hex')}${SELF_AUTH_TLD}`;
}

/**
 * Extract the base64-encoded pubkey from a self-auth fqdn.
 * Returns null if the fqdn is not a valid .id address.
 */
export function pubkeyFromSelfAuthFqdn(fqdn: string): string | null {
  const f = fqdn.trim().toLowerCase();
  if (!f.endsWith(SELF_AUTH_TLD)) return null;
  const hex = f.slice(0, -SELF_AUTH_TLD.length);
  if (!/^[0-9a-f]+$/.test(hex) || hex.length === 0 || hex.length % 2 !== 0) return null;
  return Buffer.from(hex, 'hex').toString('base64');
}

/** Returns true when fqdn or lp:// address is a self-authenticating .id address. */
export function isSelfAuthAddress(address: string): boolean {
  const host = address.startsWith('lp://') ? address.slice(5).split('/')[0] ?? '' : address;
  return host.trim().toLowerCase().endsWith(SELF_AUTH_TLD);
}

/**
 * Full lp:// URL for a self-auth address.
 * Accepts either a raw fqdn or a base64 pubkey (via deriveSelfAuthAddress).
 */
export function selfAuthLpUrl(pubkeyB64: string): string {
  return `lp://${deriveSelfAuthAddress(pubkeyB64)}`;
}
