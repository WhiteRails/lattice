import { describe, expect, it, vi } from 'vitest';
import { OverlayResponseMultiplexer } from '../node/overlay-response-multiplexer';
import type { OverlayMessage } from '../node/message';

function response(id: string): OverlayMessage {
  return {
    id, type: 'response', source: 'gateway', destination: 'entry', payload: { status: 200 }, trace: [], source_pubkey: 'key',
  };
}

describe('OverlayResponseMultiplexer', () => {
  it('correlates out-of-order responses without per-request listeners', async () => {
    const mux = new OverlayResponseMultiplexer(2, 1_000);
    const first = mux.waitFor('first');
    const second = mux.waitFor('second');
    expect(mux.size).toBe(2);
    expect(mux.resolve(response('second'))).toBe(true);
    expect(mux.resolve(response('first'))).toBe(true);
    await expect(second).resolves.toMatchObject({ id: 'second' });
    await expect(first).resolves.toMatchObject({ id: 'first' });
    expect(mux.size).toBe(0);
  });

  it('bounds pending work and clears timed-out or disconnected requests', async () => {
    vi.useFakeTimers();
    try {
      const mux = new OverlayResponseMultiplexer(1, 100);
      const first = mux.waitFor('first');
      await expect(mux.waitFor('second')).rejects.toThrow(/capacity/i);
      vi.advanceTimersByTime(100);
      await expect(first).rejects.toThrow(/timeout/i);
      expect(mux.size).toBe(0);
      const pending = mux.waitFor('third');
      mux.close();
      await expect(pending).rejects.toThrow(/disconnected/i);
    } finally {
      vi.useRealTimers();
    }
  });
});
