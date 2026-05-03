import * as crypto from 'crypto';

/**
 * Base32 character set (RFC 4648)
 */
const ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';

/**
 * Simple Base32 encoder for WhiteNet addresses
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
 * Generates a WhiteNet address from a public key.
 * Formula: white_address = base32(sha256(public_key))[0:32] + ".white"
 */
export function generateWhiteAddress(publicKey: string): string {
  const hash = crypto.createHash('sha256').update(publicKey).digest();
  const encoded = base32Encode(hash);
  return `${encoded.slice(0, 32)}.white`;
}
