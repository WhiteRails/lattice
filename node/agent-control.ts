import { EventEmitter } from 'events';
import { ChildProcess } from 'child_process';

/**
 * AgentControlBus: module-level singleton EventEmitter that bridges
 * the gateway (which produces pause_agent decisions) to the runner
 * (which holds child process handles).
 *
 * For testnet (in-process topology). Production multi-process
 * deployments should extend this with a Unix domain socket transport.
 */
class AgentControlBus extends EventEmitter {
  // Map of registered agent processes
  private agents = new Map<string, ChildProcess>();
  // Queue for pause events that arrive before agent registration
  private pendingPause = new Map<string, true>();
  // Kill timers tracked to prevent leaks
  private killTimers = new Map<string, NodeJS.Timeout>();

  registerAgent(agentName: string, child: ChildProcess): void {
    this.agents.set(agentName, child);
    // Drain pending pause queue
    if (this.pendingPause.has(agentName)) {
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
      this.pendingPause.set(agentName, true);
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
    }, 5000);
    killTimer.unref();
    this.killTimers.set(agentName, killTimer);

    // Remove from active registry without cancelling the kill timer
    this.agents.delete(agentName);
    this.pendingPause.delete(agentName);
  }
}

// Singleton export
export const controlBus = new AgentControlBus();
