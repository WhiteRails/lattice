/**
 * Small LRU cache for verified control-plane lookups.
 *
 * It is deliberately a cache, not a source of authority: callers choose a
 * short TTL and revalidate from the original signed/on-chain source on miss.
 */
interface CacheValue<V> {
  value: V;
  expiresAtMs: number;
}

export class BoundedTtlCache<K, V> {
  private readonly values = new Map<K, CacheValue<V>>();

  constructor(private readonly maxEntries: number) {
    if (!Number.isSafeInteger(maxEntries) || maxEntries < 1) {
      throw new Error('TTL cache maxEntries must be a positive integer');
    }
  }

  get size(): number { return this.values.size; }

  delete(key: K): boolean {
    return this.values.delete(key);
  }

  clear(): void {
    this.values.clear();
  }

  get(key: K, now = Date.now()): V | undefined {
    const item = this.values.get(key);
    if (!item) return undefined;
    if (item.expiresAtMs <= now) {
      this.values.delete(key);
      return undefined;
    }
    // Map insertion order supplies LRU ordering without a second index.
    this.values.delete(key);
    this.values.set(key, item);
    return item.value;
  }

  set(key: K, value: V, ttlMs: number, now = Date.now()): void {
    if (!Number.isSafeInteger(ttlMs) || ttlMs < 1) throw new Error('TTL cache ttlMs must be positive');
    this.values.delete(key);
    while (this.values.size >= this.maxEntries) {
      const oldest = this.values.keys().next().value as K | undefined;
      if (oldest === undefined) break;
      this.values.delete(oldest);
    }
    this.values.set(key, { value, expiresAtMs: now + ttlMs });
  }
}
