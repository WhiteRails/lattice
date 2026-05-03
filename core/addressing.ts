import * as crypto from 'crypto';

/**
 * Base32 character set (RFC 4648)
 */
const ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';

/**
 * Simple Base32 encoder for Lattice addresses
 */
function base32Encode(buffer: Buffer): string {
  let bits = 0;
  let value = 0;
  let output = '';

  for (let i = 0; i < buffer.length; i++) {
    value = (value << 8) | buffer[i];
    bits += 8;

    while (bits >= 5) {
      output += ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }

  if (bits > 0) {
    output += ALPHABET[(value << (5 - bits)) & 31];
  }

  return output;
}

/**
 * Default stable subject for a registry name when the operator does not supply a DID.
 */
export function deriveDefaultSubjectId(name: string): string {
  const h = crypto.createHash('sha256').update(name, 'utf8').digest('hex');
  return `did:traceveil:lattice:${h.slice(0, 32)}`;
}

/**
 * 32-char base32 suffix for `.lattice` addresses derived from **subject_id** (whitepaper §6.1).
 */
export function hashSubjectForLatticeSuffix(subjectId: string): string {
  const hash = crypto.createHash('sha256').update(subjectId, 'utf8').digest();
  const encoded = base32Encode(hash);
  return encoded.slice(0, 32);
}

export function generateWhiteAddressFromSubjectId(subjectId: string): string {
  return `${hashSubjectForLatticeSuffix(subjectId)}.lattice`;
}

/**
 * Generates a Lattice address from a public key.
 * @deprecated Prefer {@link generateWhiteAddressFromSubjectId} with a stable `subject_id`.
 * This derives a synthetic subject from the public key material for backwards compatibility.
 */
export function generateWhiteAddress(publicKey: string): string {
  const syntheticSubject = `did:traceveil:key:${crypto.createHash('sha256').update(publicKey, 'utf8').digest('hex')}`;
  return generateWhiteAddressFromSubjectId(syntheticSubject);
}
