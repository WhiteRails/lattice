import { EventEmitter } from 'events';
import { ChildProcess } from 'child_process';
import { BoundedTtlCache } from './bounded-ttl-cache';

const DEFAULT_MAX_CONTROLLED_AGENTS = 8_192;
const DEFAULT_PENDING_PAUSE_TTL_MS = 60_000;
const DEFAULT_KILL_GRACE_MS = 5_000;

export interface AgentControlBusOptions {
  maxAgents?: number;
  maxPendingPauses?: number;
  pendingPauseTtlMs?: number;
  killGraceMs?: number;
}

function boundedOption(value: number | undefined, fallback: number, min: number, max: number, name: string): number {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < min || resolved > max) {
    throw new Error(`${name} must be between ${min} and ${max}`);
  }
  return resolved;
}

/**
 * AgentControlBus: module-level singleton EventEmitter that bridges
 * the gateway (which produces pause_agent decisions) to the runner
 * (which holds child process handles).
 *
 * For testnet (in-process topology). Production multi-process
 * deployments should extend this with a Unix domain socket transport.
 */
export class AgentControlBus extends EventEmitter {
  // Map of registered agent processes
  private readonly agents = new Map<string, ChildProcess>();
  // Queue for pause events that arrive before agent registration. This only
  // bridges a short startup race: it is not durable policy state.
  private readonly pendingPause: BoundedTtlCache<string, true>;
  // Kill timers tracked to prevent leaks
  private readonly killTimers = new Map<string, NodeJS.Timeout>();
  private readonly maxAgents: number;
  private readonly pendingPauseTtlMs: number;
  private readonly killGraceMs: number;

  constructor(options: AgentControlBusOptions = {}) {
    super();
    this.maxAgents = boundedOption(options.maxAgents, DEFAULT_MAX_CONTROLLED_AGENTS, 1, 65_536, 'maxAgents');
    const maxPendingPauses = boundedOption(options.maxPendingPauses, this.maxAgents, 1, 65_536, 'maxPendingPauses');
    this.pendingPauseTtlMs = boundedOption(options.pendingPauseTtlMs, DEFAULT_PENDING_PAUSE_TTL_MS, 1, 300_000, 'pendingPauseTtlMs');
    this.killGraceMs = boundedOption(options.killGraceMs, DEFAULT_KILL_GRACE_MS, 1, 60_000, 'killGraceMs');
    this.pendingPause = new BoundedTtlCache(maxPendingPauses);
  }

  snapshot(): { activeAgents: number; pendingPauses: number; pendingKills: number; maxAgents: number } {
    return {
      activeAgents: this.agents.size,
      pendingPauses: this.pendingPause.size,
      pendingKills: this.killTimers.size,
      maxAgents: this.maxAgents,
    };
  }

  registerAgent(agentName: string, child: ChildProcess): void {
    const existing = this.agents.get(agentName);
    if (existing && existing !== child) {
      try { child.kill('SIGTERM'); } catch {}
      throw new Error(`Agent '${agentName}' is already registered`);
    }
    if (!existing && this.agents.size >= this.maxAgents) {
      // The child was already spawned by the runner. Stop it rather than
      // leaving an untracked process outside the bounded control plane.
      try { child.kill('SIGTERM'); } catch {}
      throw new Error(`Agent control capacity exhausted (${this.maxAgents})`);
    }
    this.agents.set(agentName, child);
    // Drain pending pause queue
    if (this.pendingPause.get(agentName)) {
      this.pendingPause.delete(agentName);
      this.executeKill(agentName, child);
    }
  }

  unregisterAgent(agentName: string): void {
    this.agents.delete(agentName);
    this.pendingPause.delete(agentName);
    const timer = this.killTimers.get(agentName);
    if (timer) { clearTimeout(timer); this.killTimers.delete(agentName); }
  }

  pauseAgent(agentName: string): void {
    const child = this.agents.get(agentName);
    if (child) {
      this.executeKill(agentName, child);
    } else {
      // Queue for when agent registers (handles startup race condition)
      this.pendingPause.set(agentName, true, this.pendingPauseTtlMs);
    }
  }

  private executeKill(agentName: string, child: ChildProcess): void {
    console.warn(JSON.stringify({
      level: 'WARN',
      event: 'agent_killed',
      agent: agentName,
      method: 'SIGTERM',
      source: 'control_bus',
      timestamp: new Date().toISOString(),
    }));

    // Send SIGTERM first
    try { child.kill('SIGTERM'); } catch {}

    // If still alive after 5s, SIGKILL
    const killTimer = setTimeout(() => {
      this.killTimers.delete(agentName);
      if (child.exitCode === null && !child.killed) {
        console.warn(JSON.stringify({
          level: 'WARN',
          event: 'agent_killed',
          agent: agentName,
          method: 'SIGKILL',
          source: 'control_bus',
          timestamp: new Date().toISOString(),
        }));
        try { child.kill('SIGKILL'); } catch {}
      }
    }, this.killGraceMs);
    killTimer.unref();
    this.killTimers.set(agentName, killTimer);

    // Remove from active registry without cancelling the kill timer
    this.agents.delete(agentName);
    this.pendingPause.delete(agentName);
  }
}

// Singleton export
export const controlBus = new AgentControlBus();
