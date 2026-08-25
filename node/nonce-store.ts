/**
 * Bounded replay cache with O(log n) inserts and O(expired) cleanup.
 *
 * A previous implementation scanned every live nonce on each request. That
 * turns a five-minute replay window into O(requests²) work under load. The
 * min-heap keeps the authoritative expiry order while the map gives O(1)
 * replay lookups. Capacity is deliberately fail-closed: evicting a live nonce
 * would reopen a replay window.
 */
interface ExpiringNonce {
  nonce: string;
  expiresAt: number;
}

const DEFAULT_MAX_ENTRIES = 1_000_000;

export class NonceStore {
  private readonly store = new Map<string, number>();
  private readonly expiryHeap: ExpiringNonce[] = [];

  constructor(private readonly maxSize = getReplayStoreMaxEntries()) {
    if (!Number.isSafeInteger(maxSize) || maxSize < 1) throw new Error('NonceStore maxSize must be positive');
  }

  get size(): number {
    return this.store.size;
  }

  // Returns false if nonce already exists, or capacity is exhausted.
  add(nonce: string, ttlMs: number): boolean {
    const now = Date.now();
    this.cleanup(now);
    if (this.store.has(nonce)) return false;
    if (!Number.isFinite(ttlMs) || ttlMs <= 0 || this.store.size >= this.maxSize) return false;
    const expiresAt = now + ttlMs;
    this.store.set(nonce, expiresAt);
    this.push({ nonce, expiresAt });
    return true;
  }

  private cleanup(now: number): void {
    while (this.expiryHeap.length && this.expiryHeap[0]!.expiresAt <= now) {
      const expired = this.pop()!;
      // Defensive check in case a future implementation renews a nonce.
      if (this.store.get(expired.nonce) === expired.expiresAt) this.store.delete(expired.nonce);
    }
  }

  private push(value: ExpiringNonce): void {
    this.expiryHeap.push(value);
    let child = this.expiryHeap.length - 1;
    while (child > 0) {
      const parent = Math.floor((child - 1) / 2);
      if (this.expiryHeap[parent]!.expiresAt <= value.expiresAt) break;
      this.expiryHeap[child] = this.expiryHeap[parent]!;
      child = parent;
    }
    this.expiryHeap[child] = value;
  }

  private pop(): ExpiringNonce | undefined {
    const first = this.expiryHeap[0];
    const last = this.expiryHeap.pop();
    if (!first || !last || this.expiryHeap.length === 0) return first;
    let parent = 0;
    while (true) {
      const left = parent * 2 + 1;
      if (left >= this.expiryHeap.length) break;
      const right = left + 1;
      const child = right < this.expiryHeap.length &&
        this.expiryHeap[right]!.expiresAt < this.expiryHeap[left]!.expiresAt ? right : left;
      if (this.expiryHeap[child]!.expiresAt >= last.expiresAt) break;
      this.expiryHeap[parent] = this.expiryHeap[child]!;
      parent = child;
    }
    this.expiryHeap[parent] = last;
    return first;
  }
}

export function getReplayStoreMaxEntries(): number {
  const envVal = process.env.LATTICE_REPLAY_MAX_ENTRIES;
  if (envVal) {
    const parsed = Number.parseInt(envVal, 10);
    if (Number.isSafeInteger(parsed) && parsed >= 10_000 && parsed <= 10_000_000) return parsed;
  }
  return DEFAULT_MAX_ENTRIES;
}

export function getReplayWindowMs(): number {
  const envVal = process.env.LATTICE_REPLAY_WINDOW_MS;
  if (envVal) {
    const parsed = parseInt(envVal, 10);
    if (Number.isFinite(parsed) && parsed >= 30_000) return parsed;
  }
  return 5 * 60_000; // default 5 minutes
}
