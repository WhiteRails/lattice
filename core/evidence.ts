import * as crypto from 'crypto';
import { EncryptedEvidence, EncryptedEvidenceSchema } from './types';

export interface EvidenceBundle {
  action_id: string;
  request: unknown;
  response: unknown;
  parameters: unknown;
  agent_id: string;
  tool_id: string;
  timestamp: string;
}

export interface Recipient {
  id: string;
  /** RSA public key PEM for key wrapping */
  publicKey: string;
}

/**
 * EvidenceStore — AES-256-GCM encrypted evidence bundles with
 * multi-recipient RSA key wrapping (§11).
 *
 * Privacy model: the ciphertext is stored once; each recipient gets
 * an RSA-wrapped copy of the AES key. Only designated parties can decrypt.
 *
 * Designated recipients (§11):
 *   - user / agent owner
 *   - organization compliance
 *   - approved auditor
 *   - regulator (when legally required)
 */
export class EvidenceStore {
  private store: Map<string, EncryptedEvidence> = new Map();

  /**
   * Encrypts and stores an evidence bundle for the given recipients.
   * Returns the EncryptedEvidence with a wp-evidence:// reference.
   */
  async store_bundle(bundle: EvidenceBundle, recipients: Recipient[]): Promise<EncryptedEvidence> {
    const plaintext = Buffer.from(JSON.stringify(bundle), 'utf-8');

    // Generate a random 256-bit AES key and IV
    const aesKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12);

    const cipher = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();

    // Wrap the AES key for each recipient using RSA-OAEP
    const wrapped_keys: Record<string, string> = {};
    for (const r of recipients) {
      const wrapped = crypto.publicEncrypt(
        { key: r.publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
        aesKey,
      );
      wrapped_keys[r.id] = wrapped.toString('base64');
    }

    const ref = `wp-evidence://${bundle.action_id}`;
    const evidence = EncryptedEvidenceSchema.parse({
      ref,
      action_id: bundle.action_id,
      created_at: new Date().toISOString(),
      ciphertext: encrypted.toString('hex'),
      auth_tag: authTag.toString('hex'),
      iv: iv.toString('hex'),
      wrapped_keys,
    });

    this.store.set(ref, evidence);
    return evidence;
  }

  /**
   * Retrieves and decrypts an evidence bundle using a recipient's RSA private key.
   */
  async retrieve(ref: string, recipientId: string, recipientPrivateKey: string): Promise<EvidenceBundle> {
    const evidence = this.store.get(ref);
    if (!evidence) throw new Error(`Evidence bundle not found: ${ref}`);

    const wrappedKey = evidence.wrapped_keys[recipientId];
    if (!wrappedKey) throw new Error(`No wrapped key for recipient: ${recipientId}`);

    // Unwrap AES key
    const aesKey = crypto.privateDecrypt(
      { key: recipientPrivateKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING },
      Buffer.from(wrappedKey, 'base64'),
    );

    // Decrypt
    const decipher = crypto.createDecipheriv(
      'aes-256-gcm',
      aesKey,
      Buffer.from(evidence.iv, 'hex'),
    );
    decipher.setAuthTag(Buffer.from(evidence.auth_tag, 'hex'));
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(evidence.ciphertext, 'hex')),
      decipher.final(),
    ]);

    return JSON.parse(plaintext.toString('utf-8')) as EvidenceBundle;
  }

  get(ref: string): EncryptedEvidence | undefined {
    return this.store.get(ref);
  }

  listRefs(): string[] {
    return [...this.store.keys()];
  }
}
