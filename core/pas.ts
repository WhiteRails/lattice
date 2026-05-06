import { createHmac, timingSafeEqual } from 'crypto';
import * as fs from 'fs';
import { PASScore, PASScoreSchema } from './types';

interface PASStateFile {
  version: 1;
  scores: Record<string, { score: number; factors: PASScore['factors']; updated_at: string; hmac: string }>;
}

export class PowerAccumulationTracker {
  private scores: Map<string, PASScore> = new Map();
  private threshold: number = 100;
  private savePath: string | null = null;
  private hmacKey: string | null = null;
  private saveTimer: NodeJS.Timeout | null = null;

  /**
   * Configures the auto-save path and HMAC key.
   */
  setSavePath(filePath: string, hmacKey: string): void {
    this.savePath = filePath;
    this.hmacKey = hmacKey;
  }

  /**
   * Initializes or gets the PAS for an agent.
   */
  getScore(agent_id: string): PASScore {
    let score = this.scores.get(agent_id);
    if (!score) {
      score = PASScoreSchema.parse({
        score: 0,
        factors: {},
        last_updated: new Date().toISOString(),
      });
      this.scores.set(agent_id, score);
    }
    return score;
  }

  /**
   * Records an action and updates the PAS.
   */
  recordAction(agent_id: string, updates: Partial<PASScore['factors']>): PASScore {
    const current = this.getScore(agent_id);

    const newFactors = { ...current.factors };
    let scoreIncrease = 0;

    for (const [key, value] of Object.entries(updates)) {
      if (value !== undefined) {
        (newFactors as any)[key] += value;
        // Simple heuristic for score calculation
        scoreIncrease += value * this.getFactorWeight(key);
      }
    }

    const updatedScore: PASScore = {
      score: current.score + scoreIncrease,
      factors: newFactors,
      last_updated: new Date().toISOString(),
    };

    this.scores.set(agent_id, updatedScore);

    if (updatedScore.score >= this.threshold * 0.8) {
      console.warn(JSON.stringify({
        level: "WARN",
        event: "pas_warning",
        agent_id,
        score: updatedScore.score,
        threshold: this.threshold,
        factors: updatedScore.factors,
        timestamp: new Date().toISOString(),
      }));
    }

    this.scheduleSave();

    return updatedScore;
  }

  /**
   * Saves all scores to a file with per-entry HMAC integrity.
   */
  save(filePath: string, hmacKey: string): void {
    const scores: PASStateFile['scores'] = {};
    for (const [agentId, entry] of this.scores) {
      const payload = JSON.stringify({ agentId, score: entry.score, factors: entry.factors });
      const hmac = createHmac('sha256', hmacKey).update(payload).digest('hex');
      scores[agentId] = {
        score: entry.score,
        factors: entry.factors,
        updated_at: entry.last_updated,
        hmac,
      };
    }
    const data: PASStateFile = { version: 1, scores };
    fs.writeFileSync(filePath, JSON.stringify(data), { mode: 0o600 });
  }

  /**
   * Loads scores from a file, verifying per-entry HMAC integrity.
   * Entries that fail verification are skipped with a warning.
   */
  load(filePath: string, hmacKey: string): void {
    const raw = fs.readFileSync(filePath, 'utf-8');
    const data: PASStateFile = JSON.parse(raw);
    for (const [agentId, entry] of Object.entries(data.scores)) {
      const payload = JSON.stringify({ agentId, score: entry.score, factors: entry.factors });
      const expected = createHmac('sha256', hmacKey).update(payload).digest('hex');
      const hmacBuf = Buffer.from(entry.hmac, 'hex');
      const expectedBuf = Buffer.from(expected, 'hex');
      if (hmacBuf.length !== expectedBuf.length || !timingSafeEqual(hmacBuf, expectedBuf)) {
        console.warn(JSON.stringify({
          level: "WARN",
          event: "pas_tamper_detected",
          agent_id: agentId,
          timestamp: new Date().toISOString(),
        }));
        continue;
      }
      const parsed = PASScoreSchema.parse({
        score: entry.score,
        factors: entry.factors,
        last_updated: entry.updated_at,
      });
      this.scores.set(agentId, parsed);
    }
  }

  /**
   * Schedules a debounced auto-save (1 second).
   */
  private scheduleSave(): void {
    if (this.savePath === null || this.hmacKey === null) return;
    if (this.saveTimer !== null) {
      clearTimeout(this.saveTimer);
    }
    const filePath = this.savePath;
    const hmacKey = this.hmacKey;
    this.saveTimer = setTimeout(() => {
      this.saveTimer = null;
      this.save(filePath, hmacKey);
    }, 1000);
  }

  /**
   * Returns weights for different power accumulation factors.
   */
  private getFactorWeight(factor: string): number {
    const weights: Record<string, number> = {
      compute_acquired: 10,
      money_accessible: 5,
      credentials_created: 20,
      infrastructure_modified: 15,
      code_deployed: 25,
      humans_contacted: 10,
      reach_expanded: 15,
      identity_multiplied: 30,
      persistence_increased: 20,
      agent_replication_attempted: 50,
      sensitive_data_accessed: 10,
    };
    return weights[factor] || 1;
  }
}
