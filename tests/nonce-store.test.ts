import { describe, expect, it, vi } from 'vitest';
import { NonceStore } from '../node/nonce-store';

describe('NonceStore', () => {
  it('fails closed at capacity and reclaims only expired nonces', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-01-01T00:00:00.000Z'));
    try {
      const store = new NonceStore(2);
      expect(store.add('a', 1_000)).toBe(true);
      expect(store.add('b', 10_000)).toBe(true);
      expect(store.add('c', 1_000)).toBe(false);
      expect(store.add('a', 1_000)).toBe(false);

      vi.advanceTimersByTime(1_000);
      expect(store.add('a', 1_000)).toBe(true);
      expect(store.size).toBe(2);
      expect(store.add('c', 1_000)).toBe(false);
    } finally {
      vi.useRealTimers();
    }
  });

  it('expires nonces in deadline order regardless of insertion order', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2026-01-01T00:00:00.000Z'));
    try {
      const store = new NonceStore(3);
      expect(store.add('long', 10_000)).toBe(true);
      expect(store.add('short', 1_000)).toBe(true);
      expect(store.add('middle', 5_000)).toBe(true);
      vi.advanceTimersByTime(1_000);
      expect(store.add('new', 1_000)).toBe(true);
      expect(store.add('short', 1_000)).toBe(false);
      vi.advanceTimersByTime(1_000);
      expect(store.add('short', 1_000)).toBe(true);
    } finally {
      vi.useRealTimers();
    }
  });
});
