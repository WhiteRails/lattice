import type { OverlayMessage } from './message';

interface PendingResponse {
  resolve: (message: OverlayMessage) => void;
  reject: (error: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

/**
 * Correlates many responses from one persistent inbound WebSocket without
 * installing one EventEmitter listener per request. The map is bounded and
 * timeout-cleaned, so a hidden Gateway cannot retain a cell's work forever.
 */
export class OverlayResponseMultiplexer {
  private readonly pending = new Map<string, PendingResponse>();

  constructor(private readonly maxPending: number, private readonly timeoutMs: number) {
    if (!Number.isSafeInteger(maxPending) || maxPending < 1) throw new Error('response multiplexer maxPending must be positive');
    if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1) throw new Error('response multiplexer timeoutMs must be positive');
  }

  get size(): number { return this.pending.size; }

  waitFor(id: string): Promise<OverlayMessage> {
    if (this.pending.has(id)) return Promise.reject(new Error(`Duplicate pending overlay response: ${id}`));
    if (this.pending.size >= this.maxPending) return Promise.reject(new Error(`Hidden gateway response capacity: ${this.maxPending}`));
    return new Promise<OverlayMessage>((resolve, reject) => {
      const timer = setTimeout(() => this.reject(id, new Error('hidden gateway timeout')), this.timeoutMs);
      this.pending.set(id, { resolve, reject, timer });
    });
  }

  resolve(message: OverlayMessage): boolean {
    const pending = this.pending.get(message.id);
    if (!pending) return false;
    clearTimeout(pending.timer);
    this.pending.delete(message.id);
    pending.resolve(message);
    return true;
  }

  reject(id: string, error: Error): boolean {
    const pending = this.pending.get(id);
    if (!pending) return false;
    clearTimeout(pending.timer);
    this.pending.delete(id);
    pending.reject(error);
    return true;
  }

  close(error = new Error('hidden gateway disconnected')): void {
    for (const id of [...this.pending.keys()]) this.reject(id, error);
  }
}
