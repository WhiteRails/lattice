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

describe('bounded action-log tail', () => {
  it('reads only the requested recent JSONL entries and validates the count', async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lat-tail-'));
    homes.push(home);
    process.env.LATTICE_HOME = home;
    vi.resetModules();
    const state = await import('../node/state');
    state.initDirs();
    state.appendLog({ action_id: 'one' });
    state.appendLog({ action_id: 'two' });
    state.appendLog({ action_id: 'three' });
    expect(state.tailLog(2)).toEqual([{ action_id: 'two' }, { action_id: 'three' }]);
    expect(() => state.tailLog(0)).toThrow(/between/i);
    expect(() => state.tailLog(state.MAX_TAIL_LOG_ENTRIES + 1)).toThrow(/between/i);
  });
});
