import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { afterEach, describe, expect, it } from 'vitest';
import { PowerAccumulationTracker } from '../core/pas';

const files: string[] = [];

afterEach(() => {
  for (const file of files.splice(0)) fs.rmSync(file, { force: true });
});

describe('PowerAccumulationTracker capacity', () => {
  it('fails closed rather than evicting an existing agent score', () => {
    const tracker = new PowerAccumulationTracker({ maxEntries: 1 });
    tracker.getScore('first');

    expect(() => tracker.getScore('second')).toThrow(/capacity exhausted/i);
    expect(tracker.snapshot()).toEqual({ entries: 1, maxEntries: 1 });
  });

  it('rejects an oversized persisted state before JSON parsing', () => {
    const file = path.join(os.tmpdir(), `lattice-pas-${process.pid}-${Date.now()}.json`);
    files.push(file);
    fs.writeFileSync(file, 'x'.repeat(1_025));
    const tracker = new PowerAccumulationTracker({ maxStateFileBytes: 1_024 });

    expect(() => tracker.load(file, 'test-key')).toThrow(/exceeds/i);
  });
});
