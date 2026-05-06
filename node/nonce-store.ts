// NonceStore: LRU cache with TTL for replay protection
export class NonceStore {
  private store = new Map<string, number>(); // nonce => expiry ms
  private maxSize: number;

  constructor(maxSize = 100_000) {
    this.maxSize = maxSize;
  }

  // Returns false if nonce already exists (replay detected)
  add(nonce: string, ttlMs: number): boolean {
    this.cleanup();
    const key = nonce;
    if (this.store.has(key)) return false;
    // Reject if at capacity rather than evicting unexpired nonces (prevents eviction-based replay attacks)
    if (this.store.size >= this.maxSize) {
      return false;
    }
    this.store.set(key, Date.now() + ttlMs);
    return true;
  }

  private cleanup(): void {
    const now = Date.now();
    for (const [k, exp] of this.store) {
      if (exp <= now) this.store.delete(k);
    }
  }
}

export function getReplayWindowMs(): number {
  const envVal = process.env.LATTICE_REPLAY_WINDOW_MS;
  if (envVal) {
    const parsed = parseInt(envVal, 10);
    if (Number.isFinite(parsed) && parsed >= 30_000) return parsed;
  }
  return 5 * 60_000; // default 5 minutes
}
