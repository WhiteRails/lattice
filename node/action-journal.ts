import * as fs from 'fs';
import * as path from 'path';

export interface ActionJournalOptions {
  maxEntries?: number;
  maxBytes?: number;
  /** Total retained bytes in this local durable journal before the Gateway fails closed. */
  maxRetainedBytes?: number;
  flushIntervalMs?: number;
}

interface PendingEntry {
  line: string;
  resolve: () => void;
  reject: (error: Error) => void;
}

/**
 * Bounded asynchronous JSONL journal. Callers receive completion only after the
 * batch reached the OS append API; capacity failures are explicit so a Gateway
 * can fail closed before performing an auditable side effect.
 */
export class ActionJournal {
  private readonly maxEntries: number;
  private readonly maxBytes: number;
  private readonly maxRetainedBytes: number;
  private readonly flushIntervalMs: number;
  private queued: PendingEntry[] = [];
  private queuedBytes = 0;
  private inFlight: PendingEntry[] = [];
  private inFlightBytes = 0;
  private timer: ReturnType<typeof setTimeout> | undefined;
  private writing = false;
  private closing = false;

  constructor(private readonly filePath: string, options: ActionJournalOptions = {}) {
    this.maxEntries = options.maxEntries ?? 10_000;
    this.maxBytes = options.maxBytes ?? 8 * 1024 * 1024;
    this.maxRetainedBytes = options.maxRetainedBytes ?? 1024 * 1024 * 1024;
    this.flushIntervalMs = options.flushIntervalMs ?? 5;
    if (!Number.isSafeInteger(this.maxEntries) || this.maxEntries < 1) throw new Error('Action journal maxEntries must be positive');
    if (!Number.isSafeInteger(this.maxBytes) || this.maxBytes < 1) throw new Error('Action journal maxBytes must be positive');
    if (!Number.isSafeInteger(this.maxRetainedBytes) || this.maxRetainedBytes < 1) throw new Error('Action journal maxRetainedBytes must be positive');
    if (!Number.isSafeInteger(this.flushIntervalMs) || this.flushIntervalMs < 1) throw new Error('Action journal flushIntervalMs must be positive');
  }

  append(entry: object): Promise<void> {
    if (this.closing) return Promise.reject(new Error('Action journal is closing'));
    let line: string;
    try {
      line = `${JSON.stringify(entry)}\n`;
    } catch {
      return Promise.reject(new Error('Action journal entry is not serializable'));
    }
    const bytes = Buffer.byteLength(line);
    if (bytes > this.maxBytes) return Promise.reject(new Error('Action journal entry exceeds byte limit'));
    if (this.queued.length + this.inFlight.length >= this.maxEntries || this.queuedBytes + this.inFlightBytes + bytes > this.maxBytes) {
      return Promise.reject(new Error('Action journal backpressure limit reached'));
    }
    return new Promise((resolve, reject) => {
      this.queued.push({ line, resolve, reject });
      this.queuedBytes += bytes;
      this.schedule();
    });
  }

  async close(): Promise<void> {
    this.closing = true;
    if (this.timer) clearTimeout(this.timer);
    await this.flush();
    while (this.writing) await new Promise(resolve => setTimeout(resolve, 1));
    if (this.queued.length) await this.flush();
  }

  private schedule(): void {
    if (this.writing || this.timer) return;
    if (this.queuedBytes >= this.maxBytes / 4) {
      void this.flush();
      return;
    }
    this.timer = setTimeout(() => {
      this.timer = undefined;
      void this.flush();
    }, this.flushIntervalMs);
  }

  private async flush(): Promise<void> {
    if (this.writing || !this.queued.length) return;
    this.writing = true;
    this.inFlight = this.queued;
    this.inFlightBytes = this.queuedBytes;
    this.queued = [];
    this.queuedBytes = 0;
    try {
      await fs.promises.mkdir(path.dirname(this.filePath), { recursive: true, mode: 0o700 });
      const content = this.inFlight.map(e => e.line).join('');
      const currentBytes = await existingFileSize(this.filePath);
      const nextBytes = Buffer.byteLength(content);
      // Do not silently delete audit history to make space. A local journal is
      // only a bounded spool; an operator must ship/archive it before the cell
      // can admit more side effects.
      if (currentBytes + nextBytes > this.maxRetainedBytes) {
        throw new Error(`Action journal retained-byte budget reached (${this.maxRetainedBytes})`);
      }
      await fs.promises.appendFile(this.filePath, content, { mode: 0o600 });
      for (const entry of this.inFlight) entry.resolve();
    } catch (error) {
      const journalError = error instanceof Error ? error : new Error(String(error));
      for (const entry of this.inFlight) entry.reject(journalError);
    } finally {
      this.inFlight = [];
      this.inFlightBytes = 0;
      this.writing = false;
      if (this.queued.length) this.schedule();
    }
  }
}

async function existingFileSize(filePath: string): Promise<number> {
  try {
    return (await fs.promises.stat(filePath)).size;
  } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') return 0;
    throw error;
  }
}

const DEFAULT_ACTION_JOURNAL_MAX_ENTRIES = 10_000;
const DEFAULT_ACTION_JOURNAL_MAX_BYTES = 8 * 1024 * 1024;
const DEFAULT_ACTION_JOURNAL_MAX_RETAINED_BYTES = 1024 * 1024 * 1024;
const DEFAULT_ACTION_JOURNAL_FLUSH_MS = 5;

/** Per-cell spool budgets. Invalid values prevent startup rather than audit loss. */
export function actionJournalOptionsFromEnv(env: NodeJS.ProcessEnv = process.env): ActionJournalOptions {
  return {
    maxEntries: boundedJournalInteger(env.LATTICE_ACTION_JOURNAL_MAX_ENTRIES, DEFAULT_ACTION_JOURNAL_MAX_ENTRIES, 128, 65_536, 'LATTICE_ACTION_JOURNAL_MAX_ENTRIES'),
    maxBytes: boundedJournalInteger(env.LATTICE_ACTION_JOURNAL_MAX_QUEUE_BYTES, DEFAULT_ACTION_JOURNAL_MAX_BYTES, 64 * 1024, 64 * 1024 * 1024, 'LATTICE_ACTION_JOURNAL_MAX_QUEUE_BYTES'),
    maxRetainedBytes: boundedJournalInteger(env.LATTICE_ACTION_JOURNAL_MAX_RETAINED_BYTES, DEFAULT_ACTION_JOURNAL_MAX_RETAINED_BYTES, 64 * 1024 * 1024, 1024 * 1024 * 1024 * 1024, 'LATTICE_ACTION_JOURNAL_MAX_RETAINED_BYTES'),
    flushIntervalMs: boundedJournalInteger(env.LATTICE_ACTION_JOURNAL_FLUSH_MS, DEFAULT_ACTION_JOURNAL_FLUSH_MS, 1, 1_000, 'LATTICE_ACTION_JOURNAL_FLUSH_MS'),
  };
}

function boundedJournalInteger(raw: string | undefined, fallback: number, min: number, max: number, name: string): number {
  if (raw === undefined || raw.trim() === '') return fallback;
  if (!/^[0-9]+$/.test(raw.trim())) throw new Error(`${name} must be an integer`);
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) throw new Error(`${name} must be between ${min} and ${max}`);
  return parsed;
}
