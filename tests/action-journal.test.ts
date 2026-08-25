import { afterEach, describe, expect, it } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { ActionJournal, actionJournalOptionsFromEnv } from '../node/action-journal';

const dirs: string[] = [];

afterEach(() => {
  for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

describe('ActionJournal', () => {
  it('batches concurrent actions into a durable JSONL file', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lat-journal-'));
    dirs.push(dir);
    const file = path.join(dir, 'logs', 'actions.jsonl');
    const journal = new ActionJournal(file, { flushIntervalMs: 1 });
    await Promise.all(Array.from({ length: 100 }, (_, i) => journal.append({ id: i })));
    await journal.close();
    const entries = fs.readFileSync(file, 'utf8').trim().split('\n').map(line => JSON.parse(line));
    expect(entries).toHaveLength(100);
    expect(entries.map(e => e.id).sort((a, b) => a - b)).toEqual(Array.from({ length: 100 }, (_, i) => i));
  });

  it('fails closed before accepting work beyond its bounded queue', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lat-journal-'));
    dirs.push(dir);
    const journal = new ActionJournal(path.join(dir, 'actions.jsonl'), { maxEntries: 1, flushIntervalMs: 10_000 });
    const first = journal.append({ id: 1 });
    await expect(journal.append({ id: 2 })).rejects.toThrow(/backpressure/i);
    await journal.close();
    await expect(first).resolves.toBeUndefined();
  });

  it('fails closed rather than letting the durable local spool grow forever', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lat-journal-'));
    dirs.push(dir);
    const file = path.join(dir, 'actions.jsonl');
    const journal = new ActionJournal(file, { maxBytes: 64, maxRetainedBytes: 32, flushIntervalMs: 1 });
    await journal.append({ id: 'a' });
    await expect(journal.append({ id: 'this entry exceeds the remaining retained capacity' })).rejects.toThrow(/retained-byte budget/i);
    await journal.close();
    expect(fs.readFileSync(file, 'utf8')).toContain('"a"');
  });

  it('parses bounded journal budgets from cell configuration', () => {
    expect(actionJournalOptionsFromEnv({
      LATTICE_ACTION_JOURNAL_MAX_ENTRIES: '512',
      LATTICE_ACTION_JOURNAL_MAX_QUEUE_BYTES: '131072',
      LATTICE_ACTION_JOURNAL_MAX_RETAINED_BYTES: '67108864',
      LATTICE_ACTION_JOURNAL_FLUSH_MS: '25',
    })).toEqual({ maxEntries: 512, maxBytes: 131072, maxRetainedBytes: 67108864, flushIntervalMs: 25 });
    expect(() => actionJournalOptionsFromEnv({ LATTICE_ACTION_JOURNAL_MAX_RETAINED_BYTES: 'unbounded' })).toThrow(/integer/i);
  });
});
