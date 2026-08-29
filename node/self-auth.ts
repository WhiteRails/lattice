/**
 * Self-authenticating Lattice addresses.
 *
 * Format: `<base32(x25519_pubkey)>.coral`. A 32-byte key encodes to a
 * 52-character lowercase RFC 4648 base32 label, fitting DNS's 63-character
 * limit. Human `name.coral` names remain signed aliases.
 */

export const SELF_AUTH_SUFFIX = '.coral';
export const SELF_AUTH_LABEL_LENGTH = 52;
const BASE32_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');

function rawX25519PublicKey(pubkeyB64: string): Buffer {
  const encoded = pubkeyB64.trim();
  if (!/^[A-Za-z0-9+/]{59}=$/.test(encoded)) {
    throw new Error('Invalid X25519 public key encoding');
  }
  const spki = Buffer.from(encoded, 'base64');
  if (spki.length !== 44 || !spki.subarray(0, X25519_SPKI_PREFIX.length).equals(X25519_SPKI_PREFIX)) {
    throw new Error('Invalid X25519 public key: expected canonical SPKI DER');
  }
  return spki.subarray(X25519_SPKI_PREFIX.length);
}

function base32Encode(input: Buffer): string {
  let result = '';
  let buffer = 0;
  let bits = 0;
  for (const byte of input) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      result += BASE32_ALPHABET[(buffer >> bits) & 0x1f];
    }
    buffer = bits === 0 ? 0 : buffer & ((1 << bits) - 1);
  }
  if (bits > 0) result += BASE32_ALPHABET[(buffer << (5 - bits)) & 0x1f];
  return result;
}

function base32Decode(label: string): Buffer | null {
  if (label.length !== SELF_AUTH_LABEL_LENGTH || !/^[a-z2-7]+$/.test(label)) return null;
  const result: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const character of label) {
    const value = BASE32_ALPHABET.indexOf(character);
    buffer = (buffer << 5) | value;
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      result.push((buffer >> bits) & 0xff);
    }
    buffer = bits === 0 ? 0 : buffer & ((1 << bits) - 1);
  }
  // 256 bits leave four required zero-padding bits in the final character.
  if (bits !== 4 || buffer !== 0 || result.length !== 32) return null;
  return Buffer.from(result);
}

/** Derive the canonical `<id>.coral` identity from an X25519 public key. */
export function deriveSelfAuthAddress(pubkeyB64: string): string {
  return `${base32Encode(rawX25519PublicKey(pubkeyB64))}${SELF_AUTH_SUFFIX}`;
}

/** Extract the embedded X25519 key from a canonical identity hostname. */
export function pubkeyFromSelfAuthFqdn(fqdn: string): string | null {
  const host = fqdn.trim().toLowerCase();
  if (!host.endsWith(SELF_AUTH_SUFFIX)) return null;
  const raw = base32Decode(host.slice(0, -SELF_AUTH_SUFFIX.length));
  return raw
    ? Buffer.concat([X25519_SPKI_PREFIX, raw]).toString('base64')
    : null;
}

/** True only for the reserved 52-character self-authenticating form. */
export function isSelfAuthFqdn(fqdn: string): boolean {
  return pubkeyFromSelfAuthFqdn(fqdn) !== null;
}

/** Returns true when an FQDN or lp:// address is self-authenticating. */
export function isSelfAuthAddress(address: string): boolean {
  const host = address.startsWith('lp://') ? address.slice(5).split('/')[0] ?? '' : address;
  return isSelfAuthFqdn(host);
}

/** Legacy overlay URI helper. LNP/1 browser use is `https://<id>.coral`. */
export function selfAuthLpUrl(pubkeyB64: string): string {
  return `lp://${deriveSelfAuthAddress(pubkeyB64)}`;
}
