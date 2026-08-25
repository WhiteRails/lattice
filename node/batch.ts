import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { logPath, LATTICE_DIR } from './state';
import { merkleRoot, merkleProofPath, MerkleProof } from '../core/log';

export const DEFAULT_BATCH_MAX_ACTIONS = 4_096;
export const DEFAULT_BATCH_MAX_SOURCE_BYTES = 16 * 1024 * 1024;
const MAX_BATCH_ACTIONS = 16_384;
const MAX_BATCH_SOURCE_BYTES = 64 * 1024 * 1024;
const MAX_ACTION_LOG_LINE_BYTES = 8 * 1024 * 1024;
const BATCH_CURSOR_FILENAME = 'cursor.json';
const BATCH_READ_CHUNK_BYTES = 64 * 1024;

export interface BatchMetadata {
  batch_id: string;
  merkle_root: string;
  from_timestamp: string;
  to_timestamp: string;
  action_count: number;
  created_at: string;
  actions: string[]; // action_ids included
  leaves: Array<{ action_id: string; leaf_hash: string }>;
  /** Durable journal range consumed by this batch; enables O(1) next-batch resume. */
  source_offset_start?: number;
  source_offset_end?: number;
}

export interface BatchCreateOptions {
  /** Fixed cap on Merkle leaves retained in one local segment. */
  maxActions?: number;
  /** Fixed scan budget per invocation so a large journal never causes an unbounded pause. */
  maxSourceBytes?: number;
}

interface BatchCursor {
  version: 1;
  journalPath: string;
  nextOffset: number;
}

interface JournalAction {
  action_id: string;
  timestamp?: string;
  [key: string]: unknown;
}

interface JournalScan {
  actions: JournalAction[];
  nextOffset: number;
}

/**
 * Seals the next bounded journal segment.
 *
 * The old MVP reread every action and every prior batch to discover work. This
 * cursor advances monotonically after a batch is durable, so steady-state work
 * is O(batch-size), independent of retained history.
 */
export function createBatch(options: BatchCreateOptions = {}): BatchMetadata {
  const maxActions = boundedOption(options.maxActions, DEFAULT_BATCH_MAX_ACTIONS, 1, MAX_BATCH_ACTIONS, 'maxActions');
  const maxSourceBytes = boundedOption(
    options.maxSourceBytes,
    DEFAULT_BATCH_MAX_SOURCE_BYTES,
    1,
    MAX_BATCH_SOURCE_BYTES,
    'maxSourceBytes',
  );

  const batchDir = path.join(LATTICE_DIR, 'batches');
  fs.mkdirSync(batchDir, { recursive: true, mode: 0o700 });
  const journalPath = logPath();
  const cursor = loadBatchCursor(batchDir, journalPath);
  const scan = scanNextActions(journalPath, cursor.nextOffset, maxActions, maxSourceBytes);
  if (scan.actions.length === 0) {
    // Audit denials without action_id are not Merkle action leaves. Persist the
    // consumed cursor so the next command never rescans them indefinitely.
    if (scan.nextOffset > cursor.nextOffset) saveBatchCursor(batchDir, { ...cursor, nextOffset: scan.nextOffset });
    throw new Error('No new actions to batch');
  }

  const leaves = scan.actions.map(action => crypto.createHash('sha256').update(JSON.stringify(action)).digest('hex'));
  const root = merkleRoot(leaves);

  const batch_id = `batch_${crypto.randomBytes(6).toString('hex')}`;
  const fromTs = scan.actions[0]?.timestamp ?? new Date().toISOString();
  const toTs = scan.actions[scan.actions.length - 1]?.timestamp ?? fromTs;
  const meta: BatchMetadata = {
    batch_id,
    merkle_root: '0x' + root,
    from_timestamp: fromTs,
    to_timestamp: toTs,
    action_count: scan.actions.length,
    created_at: new Date().toISOString(),
    actions: scan.actions.map(action => action.action_id),
    leaves: scan.actions.map((action, index) => ({ action_id: action.action_id, leaf_hash: leaves[index]! })),
    source_offset_start: cursor.nextOffset,
    source_offset_end: scan.nextOffset,
  };

  // Commit batch first, then cursor. A crash in between can only cause a safe
  // duplicate attempt, which recovery resolves from the persisted batch range;
  // advancing the cursor first could silently lose an auditable action.
  writeJsonAtomic(path.join(batchDir, `${batch_id}.json`), meta);
  saveBatchCursor(batchDir, { ...cursor, nextOffset: scan.nextOffset });
  return meta;
}

function scanNextActions(journalPath: string, startOffset: number, maxActions: number, maxSourceBytes: number): JournalScan {
  let stat: fs.Stats;
  try {
    stat = fs.statSync(journalPath);
  } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return { actions: [], nextOffset: startOffset };
    throw error;
  }
  if (startOffset > stat.size) startOffset = 0; // journal rotation/truncation
  const actions: JournalAction[] = [];
  let nextOffset = startOffset;
  let readOffset = startOffset;
  let scannedBytes = 0;
  let remainder = Buffer.alloc(0);
  let remainderOffset = startOffset;
  const fd = fs.openSync(journalPath, 'r');
  try {
    while (readOffset < stat.size && scannedBytes < maxSourceBytes && actions.length < maxActions) {
      const wanted = Math.min(BATCH_READ_CHUNK_BYTES, stat.size - readOffset, maxSourceBytes - scannedBytes);
      const chunk = Buffer.allocUnsafe(wanted);
      const bytesRead = fs.readSync(fd, chunk, 0, wanted, readOffset);
      if (bytesRead === 0) break;
      readOffset += bytesRead;
      scannedBytes += bytesRead;
      const data = remainder.length === 0 ? chunk.subarray(0, bytesRead) : Buffer.concat([remainder, chunk.subarray(0, bytesRead)]);
      let lineStart = 0;
      for (let index = 0; index < data.length; index++) {
        if (data[index] !== 0x0a) continue;
        const line = data.subarray(lineStart, index);
        const lineEndOffset = remainderOffset + index + 1;
        if (line.length > MAX_ACTION_LOG_LINE_BYTES) throw new Error(`Action journal line exceeds ${MAX_ACTION_LOG_LINE_BYTES} bytes`);
        if (line.length > 0) {
          let parsed: unknown;
          try {
            parsed = JSON.parse(line.toString('utf8'));
          } catch {
            throw new Error('Action journal contains invalid JSON');
          }
          if (isJournalAction(parsed)) actions.push(parsed);
        }
        nextOffset = lineEndOffset;
        lineStart = index + 1;
        if (actions.length >= maxActions) return { actions, nextOffset };
      }
      remainder = data.subarray(lineStart);
      remainderOffset += lineStart;
      if (remainder.length > MAX_ACTION_LOG_LINE_BYTES) throw new Error(`Action journal line exceeds ${MAX_ACTION_LOG_LINE_BYTES} bytes`);
    }
  } finally {
    fs.closeSync(fd);
  }
  return { actions, nextOffset };
}

function isJournalAction(value: unknown): value is JournalAction {
  return Boolean(value && typeof value === 'object' &&
    typeof (value as { action_id?: unknown }).action_id === 'string' &&
    (value as { action_id: string }).action_id.length > 0 &&
    (value as { action_id: string }).action_id.length <= 512);
}

function loadBatchCursor(batchDir: string, journalPath: string): BatchCursor {
  const cursorPath = path.join(batchDir, BATCH_CURSOR_FILENAME);
  try {
    const parsed = JSON.parse(fs.readFileSync(cursorPath, 'utf8')) as BatchCursor;
    if (parsed.version === 1 && parsed.journalPath === journalPath && Number.isSafeInteger(parsed.nextOffset) && parsed.nextOffset >= 0) {
      return parsed;
    }
  } catch {}
  // This slow path only happens when upgrading or recovering after a cursor
  // write interruption; normal batches never enumerate prior metadata.
  let maxOffset = 0;
  for (const filename of fs.readdirSync(batchDir)) {
    if (!filename.endsWith('.json') || filename === BATCH_CURSOR_FILENAME) continue;
    try {
      const meta = JSON.parse(fs.readFileSync(path.join(batchDir, filename), 'utf8')) as BatchMetadata;
      if (Number.isSafeInteger(meta.source_offset_end) && meta.source_offset_end! >= maxOffset) {
        maxOffset = meta.source_offset_end!;
      }
    } catch {
      // Unrelated/broken metadata cannot advance the journal cursor.
    }
  }
  return { version: 1, journalPath, nextOffset: maxOffset };
}

function saveBatchCursor(batchDir: string, cursor: BatchCursor): void {
  writeJsonAtomic(path.join(batchDir, BATCH_CURSOR_FILENAME), cursor);
}

function writeJsonAtomic(filePath: string, value: object): void {
  const temporary = `${filePath}.${process.pid}.${crypto.randomBytes(6).toString('hex')}.tmp`;
  fs.writeFileSync(temporary, JSON.stringify(value, null, 2), { mode: 0o600 });
  fs.renameSync(temporary, filePath);
  fs.chmodSync(filePath, 0o600);
}

function boundedOption(value: number | undefined, fallback: number, min: number, max: number, name: string): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < min || resolved > max) {
    throw new Error(`${name} must be between ${min} and ${max}`);
  }
  return resolved;
}

export function generateProof(actionId: string): { batch: BatchMetadata, proof: MerkleProof } {
  const batchDir = path.join(LATTICE_DIR, 'batches');
  if (!fs.existsSync(batchDir)) throw new Error("No batches found");

  const existingBatches = fs.readdirSync(batchDir).filter(f => f.endsWith('.json'));
  let targetBatch: BatchMetadata | undefined;
  
  for (const b of existingBatches) {
    const meta: BatchMetadata = JSON.parse(fs.readFileSync(path.join(batchDir, b), 'utf-8'));
    if (meta.actions.includes(actionId)) {
      targetBatch = meta;
      break;
    }
  }

  if (!targetBatch) throw new Error(`Action ${actionId} not found in any batch`);

  const leaves = targetBatch.leaves?.map(l => l.leaf_hash);
  if (!leaves?.length) {
    throw new Error(`Batch ${targetBatch.batch_id} does not contain sealed leaves`);
  }
  
  const idx = targetBatch.actions.indexOf(actionId);
  const pathArr = merkleProofPath(leaves, idx);

  return {
    batch: targetBatch,
    proof: {
      action_id: actionId,
      leaf_hash: leaves[idx],
      path: pathArr,
      root: targetBatch.merkle_root.replace('0x', '')
    }
  };
}
