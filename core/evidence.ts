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

export interface EvidenceStoreOptions {
  /** Maximum locally retained evidence records. */
  maxEntries?: number;
  /** Aggregate retained encrypted bytes. New evidence fails closed above it. */
  maxRetainedBytes?: number;
  /** Maximum serialized plaintext bundle accepted before encryption. */
  maxBundleBytes?: number;
  /** Maximum recipients (and RSA wraps) per evidence bundle. */
  maxRecipients?: number;
  /** Default administrative page size. */
  pageSize?: number;
}

const DEFAULT_MAX_ENTRIES = 100_000;
const DEFAULT_MAX_RETAINED_BYTES = 1024 * 1024 * 1024;
const DEFAULT_MAX_BUNDLE_BYTES = 4 * 1024 * 1024;
const DEFAULT_MAX_RECIPIENTS = 64;
const DEFAULT_PAGE_SIZE = 1_000;

function boundedOption(value: number | undefined, fallback: number, min: number, max: number, name: string): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < min || resolved > max) {
    throw new Error(`${name} must be between ${min} and ${max}`);
  }
  return resolved;
}

function serializedEvidenceBytes(evidence: EncryptedEvidence): number {
  return Buffer.byteLength(JSON.stringify(evidence), 'utf8');
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
  private readonly store = new Map<string, EncryptedEvidence>();
  private readonly maxEntries: number;
  private readonly maxRetainedBytes: number;
  private readonly maxBundleBytes: number;
  private readonly maxRecipients: number;
  private readonly pageSize: number;
  private retainedBytes = 0;

  constructor(options: EvidenceStoreOptions = {}) {
    this.maxEntries = boundedOption(options.maxEntries, DEFAULT_MAX_ENTRIES, 1, 1_000_000, 'maxEntries');
    this.maxRetainedBytes = boundedOption(
      options.maxRetainedBytes,
      DEFAULT_MAX_RETAINED_BYTES,
      1,
      1024 * 1024 * 1024 * 1024,
      'maxRetainedBytes',
    );
    this.maxBundleBytes = boundedOption(options.maxBundleBytes, DEFAULT_MAX_BUNDLE_BYTES, 1, 64 * 1024 * 1024, 'maxBundleBytes');
    this.maxRecipients = boundedOption(options.maxRecipients, DEFAULT_MAX_RECIPIENTS, 1, 1_024, 'maxRecipients');
    this.pageSize = boundedOption(options.pageSize, DEFAULT_PAGE_SIZE, 1, 10_000, 'pageSize');
  }

  snapshot(): { entries: number; retainedBytes: number; maxEntries: number; maxRetainedBytes: number } {
    return {
      entries: this.store.size,
      retainedBytes: this.retainedBytes,
      maxEntries: this.maxEntries,
      maxRetainedBytes: this.maxRetainedBytes,
    };
  }

  /**
   * Encrypts and stores an evidence bundle for the given recipients.
   * Returns the EncryptedEvidence with a wp-evidence:// reference.
   */
  async store_bundle(
    bundle: EvidenceBundle,
    recipients: Recipient[],
    cryptoBinding: { encryption_key_id: string; period_id?: string },
  ): Promise<EncryptedEvidence> {
    return this.encryptAndStore(bundle, recipients, cryptoBinding, false);
  }

  private async encryptAndStore(
    bundle: EvidenceBundle,
    recipients: Recipient[],
    cryptoBinding: { encryption_key_id: string; period_id?: string },
    replaceExisting: boolean,
  ): Promise<EncryptedEvidence> {
    if (!Array.isArray(recipients) || recipients.length < 1 || recipients.length > this.maxRecipients) {
      throw new Error(`Evidence recipient count must be between 1 and ${this.maxRecipients}`);
    }
    const recipientIds = new Set<string>();
    for (const recipient of recipients) {
      if (!recipient.id || recipient.id.length > 512 || recipientIds.has(recipient.id)) {
        throw new Error('Evidence recipients must have unique, bounded IDs');
      }
      if (!recipient.publicKey || Buffer.byteLength(recipient.publicKey, 'utf8') > 16 * 1024) {
        throw new Error('Evidence recipient public key exceeds byte limit');
      }
      recipientIds.add(recipient.id);
    }
    let plaintextJson: string;
    try {
      plaintextJson = JSON.stringify(bundle);
    } catch {
      throw new Error('Evidence bundle is not serializable');
    }
    const plaintext = Buffer.from(plaintextJson, 'utf-8');
    if (plaintext.byteLength > this.maxBundleBytes) {
      throw new Error(`Evidence bundle exceeds byte limit (${this.maxBundleBytes})`);
    }
    const ref = `wp-evidence://${bundle.action_id}`;
    const existing = this.store.get(ref);
    if (existing && !replaceExisting) throw new Error(`Evidence bundle '${bundle.action_id}' is already stored`);
    if (!existing && this.store.size >= this.maxEntries) {
      throw new Error(`Evidence shard capacity exhausted (${this.maxEntries})`);
    }

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

    const evidence = EncryptedEvidenceSchema.parse({
      ref,
      action_id: bundle.action_id,
      created_at: new Date().toISOString(),
      encryption_key_id: cryptoBinding.encryption_key_id,
      period_id: cryptoBinding.period_id,
      exposure_status: 'CONFIDENTIAL',
      ciphertext: encrypted.toString('hex'),
      auth_tag: authTag.toString('hex'),
      iv: iv.toString('hex'),
      wrapped_keys,
    });

    const nextBytes = serializedEvidenceBytes(evidence);
    const priorBytes = existing ? serializedEvidenceBytes(existing) : 0;
    if (this.retainedBytes - priorBytes + nextBytes > this.maxRetainedBytes) {
      throw new Error(`Evidence retained-byte budget reached (${this.maxRetainedBytes})`);
    }
    this.store.set(ref, evidence);
    this.retainedBytes = this.retainedBytes - priorBytes + nextBytes;
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

  /**
   * Re-wraps the bundle AES key for a new encryption key id (post rotation / new recipients).
   * Old ciphertext is decrypted with a recipient key, then re-encrypted with a fresh DEK.
   */
  async re_encrypt_bundle(params: {
    ref: string;
    decrypt_as_recipient_id: string;
    recipient_private_key: string;
    new_encryption_key_id: string;
    new_period_id?: string;
    new_recipients: Recipient[];
  }): Promise<EncryptedEvidence> {
    const bundle = await this.retrieve(params.ref, params.decrypt_as_recipient_id, params.recipient_private_key);
    return this.encryptAndStore(bundle, params.new_recipients, {
      encryption_key_id: params.new_encryption_key_id,
      period_id: params.new_period_id,
    }, true);
  }

  /**
   * Marks evidence as potentially exposed after encryption key compromise (metadata only;
   * ciphertext is not automatically re-wrapped here).
   */
  markPotentiallyExposed(ref: string): EncryptedEvidence {
    const ev = this.store.get(ref);
    if (!ev) throw new Error(`Evidence bundle not found: ${ref}`);
    const next = EncryptedEvidenceSchema.parse({
      ...ev,
      exposure_status: 'POTENTIALLY_EXPOSED',
    });
    this.store.set(ref, next);
    this.retainedBytes = this.retainedBytes - serializedEvidenceBytes(ev) + serializedEvidenceBytes(next);
    return next;
  }

  /** Bounded administrative page, never an unbounded evidence listing. */
  listRefs(limit = this.pageSize): string[] {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 10_000) {
      throw new Error('limit must be between 1 and 10000');
    }
    const page: string[] = [];
    for (const ref of this.store.keys()) {
      page.push(ref);
      if (page.length >= limit) break;
    }
    return page;
  }
}
