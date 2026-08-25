import * as crypto from 'crypto';
import { SAAE, RegistryTransparencyEvent } from './types';
import { hashData, hashObject } from './envelope';
import { signData } from './identity';

// ─── Internal types ──────────────────────────────────────────────────────────

export interface LogEntry {
  action_id?: string;
  payload_hash: string;
  timestamp: string;
  index: number;
  agent_id?: string;
  tool_id?: string;
  policy_decision?: string;
  event_type?: string;
  target_name?: string;
  subject_id?: string;
}

export interface MerkleProof {
  action_id: string;
  leaf_hash: string;
  path: Array<{ sibling: string; position: 'left' | 'right' }>;
  root: string;
}

export interface BatchCommitment {
  batch_id: string;
  action_count: number;
  merkle_root: string;
  timestamp: string;
  issuer: string;
  signature: string;
  start_index: number;
  leaf_hashes: string[];
}

export interface LatticeLogOptions {
  /** Retained entries in this in-memory log shard. Rotate/export before it fills. */
  maxEntries?: number;
  /** Maximum unsealed entries; append fails closed until a batch is committed. */
  maxPendingEntries?: number;
  /** Default page size for administrative listing. */
  pageSize?: number;
}

const DEFAULT_MAX_ENTRIES = 100_000;
const DEFAULT_MAX_PENDING_ENTRIES = 4_096;
const DEFAULT_PAGE_SIZE = 1_000;

function boundedOption(value: number | undefined, fallback: number, min: number, max: number, name: string): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < min || resolved > max) {
    throw new Error(`${name} must be between ${min} and ${max}`);
  }
  return resolved;
}

// ─── Merkle helpers ──────────────────────────────────────────────────────────

export function merkleRoot(leaves: string[]): string {
  if (leaves.length === 0) return hashData('empty');
  let level = [...leaves];
  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      const l = level[i];
      const r = i + 1 < level.length ? level[i + 1] : l; // duplicate last if odd
      next.push(hashData(l + r));
    }
    level = next;
  }
  return level[0];
}

export function merkleProofPath(
  leaves: string[],
  idx: number,
): Array<{ sibling: string; position: 'left' | 'right' }> {
  const path: Array<{ sibling: string; position: 'left' | 'right' }> = [];
  let level = [...leaves];
  let i = idx;
  while (level.length > 1) {
    const sibIdx = i % 2 === 0 ? i + 1 : i - 1;
    const sibling = sibIdx < level.length ? level[sibIdx] : level[i];
    path.push({ sibling, position: i % 2 === 0 ? 'right' : 'left' });
    const next: string[] = [];
    for (let j = 0; j < level.length; j += 2) {
      const l = level[j];
      const r = j + 1 < level.length ? level[j + 1] : l;
      next.push(hashData(l + r));
    }
    i = Math.floor(i / 2);
    level = next;
  }
  return path;
}

// ─── LatticeLog ────────────────────────────────────────────────────────────────

/**
 * LatticeLog — an append-only, Merkle-batched action log.
 *
 * Actions are first appended as LogEntries (indexed, hashed envelopes).
 * computeBatch() seals a window of entries into a BatchCommitment whose
 * Merkle root is signed by the log key. Any individual entry can later be
 * proven with getProof() / verifyProof().
 */
export class LatticeLog {
  private readonly entries: LogEntry[] = [];
  private readonly batches: BatchCommitment[] = [];
  private readonly actionIdToIndex = new Map<string, number>();
  private readonly agentEntryIndexes = new Map<string, number[]>();
  private readonly maxEntries: number;
  private readonly maxPendingEntries: number;
  private readonly pageSize: number;
  private nextUnbatchedIndex = 0;

  constructor(
    private readonly logId: string,
    private readonly logPrivateKey: string,
    options: LatticeLogOptions = {},
  ) {
    this.maxEntries = boundedOption(options.maxEntries, DEFAULT_MAX_ENTRIES, 1, 1_000_000, 'maxEntries');
    this.maxPendingEntries = boundedOption(
      options.maxPendingEntries,
      DEFAULT_MAX_PENDING_ENTRIES,
      1,
      this.maxEntries,
      'maxPendingEntries',
    );
    this.pageSize = boundedOption(options.pageSize, DEFAULT_PAGE_SIZE, 1, 10_000, 'pageSize');
  }

  snapshot(): { entries: number; pendingEntries: number; batches: number; maxEntries: number; maxPendingEntries: number } {
    return {
      entries: this.entries.length,
      pendingEntries: this.entries.length - this.nextUnbatchedIndex,
      batches: this.batches.length,
      maxEntries: this.maxEntries,
      maxPendingEntries: this.maxPendingEntries,
    };
  }

  // ─── Append ───────────────────────────────────────────────────────────────

  /**
   * Appends a SAAE to the log. Returns the created LogEntry.
   */
  append(saae: SAAE): LogEntry {
    this.assertAppendCapacity(saae.action_id);
    const entry: LogEntry = {
      action_id: saae.action_id,
      payload_hash: hashObject(saae),
      timestamp: saae.timestamp,
      index: this.entries.length,
      agent_id: saae.actor.agent_id,
      tool_id: saae.tool.tool_id,
      policy_decision: saae.policy.decision,
    };
    this.entries.push(entry);
    this.actionIdToIndex.set(saae.action_id, entry.index);
    this.addAgentEntry(saae.actor.agent_id, entry.index);
    return entry;
  }

  /**
   * Appends a RegistryTransparencyEvent to the transparency log.
   */
  appendRegistryEvent(event: RegistryTransparencyEvent): LogEntry {
    this.assertAppendCapacity();
    const target_name =
      event.event === 'issuer_manifest_committed' ? event.manifest_id : event.name;
    const subject_id =
      event.event === 'issuer_manifest_committed'
        ? event.manifest_content_hash
        : event.subject_id;
    const entry: LogEntry = {
      payload_hash: hashObject(event),
      timestamp: event.effective_at,
      index: this.entries.length,
      event_type: event.event,
      target_name,
      subject_id,
    };
    this.entries.push(entry);
    return entry;
  }

  // ─── Batch ────────────────────────────────────────────────────────────────

  /**
   * Seals all entries since the last batch into a signed BatchCommitment.
   */
  computeBatch(): BatchCommitment {
    const startIndex = this.nextUnbatchedIndex;
    const slice = this.entries.slice(startIndex);
    if (slice.length === 0) throw new Error('No new entries to batch');

    const leaf_hashes = slice.map(e => e.payload_hash);
    const root = merkleRoot(leaf_hashes);
    const batch_id = `batch_${crypto.randomBytes(4).toString('hex')}`;
    const unsigned = {
      batch_id,
      action_count: slice.length,
      merkle_root: root,
      timestamp: new Date().toISOString(),
      issuer: this.logId,
      start_index: startIndex,
      leaf_hashes,
    };
    const signature = signData(JSON.stringify(unsigned), this.logPrivateKey);
    const commitment: BatchCommitment = { ...unsigned, signature };
    this.batches.push(commitment);
    this.nextUnbatchedIndex = this.entries.length;
    return commitment;
  }

  // ─── Proofs ───────────────────────────────────────────────────────────────

  /**
   * Returns a Merkle inclusion proof for an action, bound to the batch that sealed it.
   */
  getProof(actionId: string): MerkleProof | undefined {
    const index = this.actionIdToIndex.get(actionId);
    const entry = index === undefined ? undefined : this.entries[index];
    if (!entry) return undefined;
    return this.merkleProofForEntry(entry);
  }

  /**
   * Merkle proof for any log entry (e.g. registry / manifest commits without action_id).
   */
  getProofByEntryIndex(entryIndex: number): MerkleProof | undefined {
    const entry = this.entries[entryIndex];
    if (!entry) return undefined;
    return this.merkleProofForEntry(entry);
  }

  private merkleProofForEntry(entry: LogEntry): MerkleProof | undefined {
    const batch = this.findBatchForEntryIndex(entry.index);
    const pending = this.entries.slice(this.nextUnbatchedIndex);
    const leaves = batch?.leaf_hashes ?? pending.map(e => e.payload_hash);
    const localIndex = batch ? entry.index - batch.start_index : entry.index - this.nextUnbatchedIndex;

    return {
      action_id: entry.action_id ?? `log-entry:${entry.index}`,
      leaf_hash: entry.payload_hash,
      path: merkleProofPath(leaves, localIndex),
      root: batch?.merkle_root ?? merkleRoot(leaves),
    };
  }

  /**
   * Verifies that a MerkleProof is valid for its declared root.
   */
  verifyProof(proof: MerkleProof): boolean {
    let current = proof.leaf_hash;
    for (const step of proof.path) {
      current = step.position === 'right'
        ? hashData(current + step.sibling)
        : hashData(step.sibling + current);
    }
    return current === proof.root;
  }

  // ─── Queries ──────────────────────────────────────────────────────────────

  /** Bounded administrative page, never an unbounded log export. */
  getEntries(limit = this.pageSize): LogEntry[] {
    this.assertPageLimit(limit);
    return this.entries.slice(0, limit);
  }

  /** Bounded administrative page, never an unbounded batch export. */
  getBatches(limit = this.pageSize): BatchCommitment[] {
    this.assertPageLimit(limit);
    return this.batches.slice(0, limit);
  }

  getEntriesForAgent(agentId: string, limit = this.pageSize): LogEntry[] {
    this.assertPageLimit(limit);
    return (this.agentEntryIndexes.get(agentId) ?? [])
      .slice(0, limit)
      .map(index => this.entries[index]!);
  }

  private assertAppendCapacity(actionId?: string): void {
    if (actionId && this.actionIdToIndex.has(actionId)) throw new Error(`Action '${actionId}' is already logged`);
    if (this.entries.length >= this.maxEntries) throw new Error(`Log shard capacity exhausted (${this.maxEntries})`);
    if (this.entries.length - this.nextUnbatchedIndex >= this.maxPendingEntries) {
      throw new Error(`Log batch backpressure limit reached (${this.maxPendingEntries})`);
    }
  }

  private addAgentEntry(agentId: string, index: number): void {
    const indexes = this.agentEntryIndexes.get(agentId) ?? [];
    indexes.push(index);
    this.agentEntryIndexes.set(agentId, indexes);
  }

  private findBatchForEntryIndex(index: number): BatchCommitment | undefined {
    let left = 0;
    let right = this.batches.length - 1;
    while (left <= right) {
      const middle = Math.floor((left + right) / 2);
      const batch = this.batches[middle]!;
      if (index < batch.start_index) {
        right = middle - 1;
      } else if (index >= batch.start_index + batch.action_count) {
        left = middle + 1;
      } else {
        return batch;
      }
    }
    return undefined;
  }

  private assertPageLimit(limit: number): void {
    if (!Number.isSafeInteger(limit) || limit < 1 || limit > 10_000) {
      throw new Error('limit must be between 1 and 10000');
    }
  }
}
