import { describe, expect, it, vi } from 'vitest';
import type { ChildProcess } from 'child_process';
import { AgentControlBus } from '../node/agent-control';

function child(): ChildProcess {
  return {
    kill: vi.fn(() => true),
    exitCode: null,
    killed: false,
  } as unknown as ChildProcess;
}

describe('AgentControlBus', () => {
  it('keeps process registration bounded and terminates an untracked overflow child', () => {
    const bus = new AgentControlBus({ maxAgents: 1 });
    const first = child();
    const overflow = child();
    bus.registerAgent('first', first);

    expect(() => bus.registerAgent('overflow', overflow)).toThrow(/capacity exhausted/i);
    expect(overflow.kill).toHaveBeenCalledWith('SIGTERM');
    expect(bus.snapshot()).toEqual({ activeAgents: 1, pendingPauses: 0, pendingKills: 0, maxAgents: 1 });
  });

  it('bounds pending pauses and drops them after the startup-race TTL', () => {
    vi.useFakeTimers();
    try {
      const bus = new AgentControlBus({ maxPendingPauses: 1, pendingPauseTtlMs: 1_000 });
      bus.pauseAgent('first');
      bus.pauseAgent('second');
      expect(bus.snapshot().pendingPauses).toBe(1);

      vi.advanceTimersByTime(1_001);
      const first = child();
      bus.registerAgent('first', first);
      expect(first.kill).not.toHaveBeenCalled();
    } finally {
      vi.useRealTimers();
    }
  });

  it('applies a pending pause exactly once when the process registers', () => {
    vi.useFakeTimers();
    try {
      const bus = new AgentControlBus({ killGraceMs: 1_000 });
      const target = child();
      bus.pauseAgent('target');
      bus.registerAgent('target', target);

      expect(target.kill).toHaveBeenCalledWith('SIGTERM');
      expect(bus.snapshot()).toEqual({ activeAgents: 0, pendingPauses: 0, pendingKills: 1, maxAgents: 8_192 });
      vi.advanceTimersByTime(1_001);
      expect(bus.snapshot().pendingKills).toBe(0);
    } finally {
      vi.useRealTimers();
    }
  });
});
