import { afterEach, describe, expect, it, vi } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

const homes: string[] = [];

afterEach(() => {
  for (const home of homes.splice(0)) fs.rmSync(home, { recursive: true, force: true });
  delete process.env.LATTICE_HOME;
  vi.resetModules();
});

async function setup(): Promise<{ home: string; appendLog: (entry: object) => void; createBatch: (options?: { maxActions?: number; maxSourceBytes?: number }) => any }> {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lat-batch-'));
  homes.push(home);
  process.env.LATTICE_HOME = home;
  vi.resetModules();
  const state = await import('../node/state');
  state.initDirs();
  const batch = await import('../node/batch');
  return { home, appendLog: state.appendLog, createBatch: batch.createBatch };
}

describe('bounded journal batching', () => {
  it('advances a durable cursor instead of rescanning previous batches', async () => {
    const { appendLog, createBatch } = await setup();
    for (let index = 0; index < 5; index++) {
      appendLog({ action_id: `act-${index}`, timestamp: `2026-01-01T00:00:0${index}.000Z`, payload: index });
    }
    const first = createBatch({ maxActions: 2, maxSourceBytes: 1024 });
    const second = createBatch({ maxActions: 2, maxSourceBytes: 1024 });
    const third = createBatch({ maxActions: 2, maxSourceBytes: 1024 });
    expect(first.actions).toEqual(['act-0', 'act-1']);
    expect(second.actions).toEqual(['act-2', 'act-3']);
    expect(third.actions).toEqual(['act-4']);
    expect(new Set([...first.actions, ...second.actions, ...third.actions]).size).toBe(5);
    expect(() => createBatch({ maxActions: 2, maxSourceBytes: 1024 })).toThrow(/No new actions/i);
  });

  it('skips non-action audit rows once and keeps the source scan bounded', async () => {
    const { appendLog, createBatch } = await setup();
    appendLog({ timestamp: '2026-01-01T00:00:00.000Z', decision: 'deny' });
    appendLog({ action_id: 'act-1', timestamp: '2026-01-01T00:00:01.000Z' });
    const meta = createBatch({ maxActions: 1, maxSourceBytes: 1_024 });
    expect(meta.actions).toEqual(['act-1']);
    expect(meta.source_offset_end).toBeGreaterThan(meta.source_offset_start!);
  });
});
