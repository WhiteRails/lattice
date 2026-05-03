import * as crypto from 'crypto';
import { SAAE, RegistryEvent } from './types';
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
  private entries: LogEntry[] = [];
  private batches: BatchCommitment[] = [];

  constructor(
    private readonly logId: string,
    private readonly logPrivateKey: string,
  ) {}

  // ─── Append ───────────────────────────────────────────────────────────────

  /**
   * Appends a SAAE to the log. Returns the created LogEntry.
   */
  append(saae: SAAE): LogEntry {
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
    return entry;
  }

  /**
   * Appends a RegistryEvent to the transparency log.
   */
  appendRegistryEvent(event: RegistryEvent): LogEntry {
    const entry: LogEntry = {
      payload_hash: hashObject(event),
      timestamp: event.effective_at,
      index: this.entries.length,
      event_type: event.event,
      target_name: event.name,
    };
    this.entries.push(entry);
    return entry;
  }

  // ─── Batch ────────────────────────────────────────────────────────────────

  /**
   * Seals all entries since the last batch into a signed BatchCommitment.
   */
  computeBatch(): BatchCommitment {
    const batched = this.batches.reduce((n, b) => n + b.action_count, 0);
    const slice = this.entries.slice(batched);
    if (slice.length === 0) throw new Error('No new entries to batch');

    const root = merkleRoot(slice.map(e => e.payload_hash));
    const batch_id = `batch_${crypto.randomBytes(4).toString('hex')}`;
    const unsigned = {
      batch_id,
      action_count: slice.length,
      merkle_root: root,
      timestamp: new Date().toISOString(),
      issuer: this.logId,
    };
    const signature = signData(JSON.stringify(unsigned), this.logPrivateKey);
    const commitment: BatchCommitment = { ...unsigned, signature };
    this.batches.push(commitment);
    return commitment;
  }

  // ─── Proofs ───────────────────────────────────────────────────────────────

  /**
   * Returns a Merkle inclusion proof for an action, computed over all entries.
   */
  getProof(actionId: string): MerkleProof | undefined {
    const entry = this.entries.find(e => e.action_id === actionId);
    if (!entry) return undefined;
    const leaves = this.entries.map(e => e.payload_hash);
    return {
      action_id: actionId,
      leaf_hash: entry.payload_hash,
      path: merkleProofPath(leaves, entry.index),
      root: merkleRoot(leaves),
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

  getEntries(): LogEntry[] {
    return [...this.entries];
  }

  getBatches(): BatchCommitment[] {
    return [...this.batches];
  }

  getEntriesForAgent(agentId: string): LogEntry[] {
    return this.entries.filter(e => e.agent_id === agentId);
  }
}
