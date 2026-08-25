/**
 * Bounded concurrent load runner for cell-level capacity and soak tests.
 *
 * It deliberately stores no request samples or principal identifiers. Latency
 * quantiles come from a fixed histogram, so a day-long run uses the same
 * memory as a one-second smoke load.
 */

export const LATENCY_BUCKETS_MS = [
  1, 2, 5, 10, 20, 50, 100, 200, 500, 1_000, 2_000, 5_000, 10_000, 30_000, 60_000,
] as const;

export interface LoadRequestResult {
  status: number;
}

export interface BoundedLoadOptions {
  durationMs: number;
  concurrency: number;
  /** Stop after this many starts even if duration remains. Useful for ramps. */
  maxRequests?: number;
  request: () => Promise<LoadRequestResult>;
  now?: () => number;
  onProgress?: (summary: BoundedLoadSummary) => void;
  progressIntervalMs?: number;
}

export interface BoundedLoadSummary {
  started: number;
  completed: number;
  failures: number;
  statusClasses: Record<'2xx' | '3xx' | '4xx' | '5xx' | 'other', number>;
  latencyHistogram: readonly number[];
  elapsedMs: number;
  requestsPerSecond: number;
  p50UpperBoundMs: number | null;
  p95UpperBoundMs: number | null;
  p99UpperBoundMs: number | null;
}

const MAX_CONCURRENCY = 65_536;
const MAX_REQUESTS = 1_000_000_000;
const MAX_DURATION_MS = 7 * 24 * 60 * 60 * 1_000;

export async function runBoundedLoad(options: BoundedLoadOptions): Promise<BoundedLoadSummary> {
  validateOptions(options);
  const now = options.now ?? Date.now;
  const startedAt = now();
  const deadline = startedAt + options.durationMs;
  const maxRequests = options.maxRequests ?? MAX_REQUESTS;
  const histogram = Array<number>(LATENCY_BUCKETS_MS.length + 1).fill(0);
  const statusClasses: BoundedLoadSummary['statusClasses'] = {
    '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0, other: 0,
  };
  let started = 0;
  let completed = 0;
  let failures = 0;
  let progressTimer: ReturnType<typeof setInterval> | undefined;

  const snapshot = (): BoundedLoadSummary => summarize(
    started, completed, failures, statusClasses, histogram, Math.max(0, now() - startedAt),
  );
  if (options.onProgress) {
    const every = options.progressIntervalMs ?? 10_000;
    progressTimer = setInterval(() => options.onProgress?.(snapshot()), every);
    progressTimer.unref?.();
  }

  const worker = async (): Promise<void> => {
    while (now() < deadline && started < maxRequests) {
      // JavaScript executes this check/increment without an await, so workers
      // cannot overshoot the global request budget.
      started++;
      const begun = now();
      try {
        const result = await options.request();
        statusClasses[statusClass(result.status)]++;
      } catch {
        failures++;
        statusClasses.other++;
      } finally {
        completed++;
        histogram[histogramIndex(Math.max(0, now() - begun))]!++;
      }
    }
  };

  try {
    await Promise.all(Array.from({ length: options.concurrency }, () => worker()));
    return snapshot();
  } finally {
    if (progressTimer) clearInterval(progressTimer);
  }
}

function validateOptions(options: BoundedLoadOptions): void {
  if (!Number.isSafeInteger(options.durationMs) || options.durationMs < 1 || options.durationMs > MAX_DURATION_MS) {
    throw new Error(`durationMs must be an integer between 1 and ${MAX_DURATION_MS}`);
  }
  if (!Number.isSafeInteger(options.concurrency) || options.concurrency < 1 || options.concurrency > MAX_CONCURRENCY) {
    throw new Error(`concurrency must be an integer between 1 and ${MAX_CONCURRENCY}`);
  }
  if (options.maxRequests !== undefined &&
      (!Number.isSafeInteger(options.maxRequests) || options.maxRequests < 1 || options.maxRequests > MAX_REQUESTS)) {
    throw new Error(`maxRequests must be an integer between 1 and ${MAX_REQUESTS}`);
  }
  if (options.progressIntervalMs !== undefined &&
      (!Number.isSafeInteger(options.progressIntervalMs) || options.progressIntervalMs < 100 || options.progressIntervalMs > 3_600_000)) {
    throw new Error('progressIntervalMs must be an integer between 100 and 3600000');
  }
}

function statusClass(status: number): keyof BoundedLoadSummary['statusClasses'] {
  if (status >= 200 && status < 300) return '2xx';
  if (status >= 300 && status < 400) return '3xx';
  if (status >= 400 && status < 500) return '4xx';
  if (status >= 500 && status < 600) return '5xx';
  return 'other';
}

function histogramIndex(latencyMs: number): number {
  const index = LATENCY_BUCKETS_MS.findIndex(bound => latencyMs <= bound);
  return index === -1 ? LATENCY_BUCKETS_MS.length : index;
}

function quantileUpperBound(histogram: readonly number[], completed: number, quantile: number): number | null {
  if (!completed) return null;
  const target = Math.max(1, Math.ceil(completed * quantile));
  let seen = 0;
  for (let index = 0; index < histogram.length; index++) {
    seen += histogram[index] ?? 0;
    if (seen >= target) return LATENCY_BUCKETS_MS[index] ?? null;
  }
  return null;
}

function summarize(
  started: number,
  completed: number,
  failures: number,
  statusClasses: BoundedLoadSummary['statusClasses'],
  histogram: readonly number[],
  elapsedMs: number,
): BoundedLoadSummary {
  return {
    started,
    completed,
    failures,
    statusClasses: { ...statusClasses },
    latencyHistogram: [...histogram],
    elapsedMs,
    requestsPerSecond: elapsedMs === 0 ? 0 : completed / (elapsedMs / 1_000),
    p50UpperBoundMs: quantileUpperBound(histogram, completed, 0.50),
    p95UpperBoundMs: quantileUpperBound(histogram, completed, 0.95),
    p99UpperBoundMs: quantileUpperBound(histogram, completed, 0.99),
  };
}
