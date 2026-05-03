import * as crypto from 'crypto';
import { SAAE, SAAESchema } from './types';
import { signData } from './identity';

/**
 * Computes SHA-256 hash of a string or buffer.
 */
export function hashData(data: string | Buffer): string {
  return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Computes SHA-256 hash of an object by stringifying it.
 */
export function hashObject(obj: any): string {
  return hashData(JSON.stringify(obj));
}

/**
 * Creates an initial SAAE structure before signing.
 */
export function createSAAEBase(params: Omit<SAAE, 'signatures' | 'schema'>): SAAE {
  const envelope: SAAE = {
    schema: 'white-protocol.action-envelope.v0.1',
    ...params,
    signatures: {
      agent_signature: '', // To be filled
    }
  };
  return envelope;
}

/**
 * Signs the SAAE using the agent's private key.
 * Only the parts of the envelope that exist before signing are included in the signature.
 */
export function signSAAE(envelope: SAAE, privateKey: string): SAAE {
  // We sign everything except the signatures themselves
  const { signatures, ...unsignedPart } = envelope;
  const signature = signData(JSON.stringify(unsignedPart), privateKey);

  return {
    ...envelope,
    signatures: {
      ...envelope.signatures,
      agent_signature: signature,
    }
  };
}
