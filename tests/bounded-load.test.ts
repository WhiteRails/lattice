import { describe, expect, it } from 'vitest';
import { LATENCY_BUCKETS_MS, runBoundedLoad } from '../node/bounded-load';

describe('bounded cell load runner', () => {
  it('caps started work, classifies results, and keeps a fixed latency histogram', async () => {
    let sequence = 0;
    const summary = await runBoundedLoad({
      durationMs: 60_000,
      concurrency: 8,
      maxRequests: 25,
      request: async () => {
        sequence++;
        if (sequence === 3) throw new Error('temporary network error');
        return { status: sequence % 2 === 0 ? 503 : 200 };
      },
    });

    expect(summary.started).toBe(25);
    expect(summary.completed).toBe(25);
    expect(summary.failures).toBe(1);
    expect(summary.statusClasses['2xx']).toBe(12);
    expect(summary.statusClasses['5xx']).toBe(12);
    expect(summary.statusClasses.other).toBe(1);
    expect(summary.latencyHistogram).toHaveLength(LATENCY_BUCKETS_MS.length + 1);
    expect(summary.latencyHistogram.reduce((total, count) => total + count, 0)).toBe(25);
  });

  it('rejects unsafe load budgets before starting work', async () => {
    await expect(runBoundedLoad({
      durationMs: 0,
      concurrency: 1,
      request: async () => ({ status: 200 }),
    })).rejects.toThrow('durationMs');
  });
});
