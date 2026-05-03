import { describe, it, expect } from 'vitest';
import { WhiteLog } from '../core/log';
import { generateKeyPair } from '../core/identity';
import { SAAE } from '../core/types';
import * as crypto from 'crypto';

function makeSAAE(agentId = 'agent-1', toolId = 'tool.a'): SAAE {
  return {
    schema: 'white-protocol.action-envelope.v0.1',
    action_id: `act_${crypto.randomUUID()}`,
    timestamp: new Date().toISOString(),
    actor: { agent_id: agentId, agent_cert_hash: 'hash:cert' },
    authority: { org_id: 'org-1', delegation_hash: 'h1', intent_anchor_hash: 'h2' },
    runtime: { runtime_cert_hash: 'hash:rt' },
    tool: { tool_id: toolId },
    policy: { decision: 'allow' },
    action: { type: 'test', target_hash: 'h3', parameter_hash: 'h4' },
    evidence: {},
    signatures: { agent_signature: 'sig' },
  };
}

describe('WhiteLog', () => {
  const { privateKey } = generateKeyPair();

  it('appends entries and indexes them correctly', () => {
    const log = new WhiteLog('log-test', privateKey);
    const s1 = makeSAAE();
    const s2 = makeSAAE();
    log.append(s1);
    log.append(s2);
    const entries = log.getEntries();
    expect(entries).toHaveLength(2);
    expect(entries[0].index).toBe(0);
    expect(entries[1].index).toBe(1);
    expect(entries[0].action_id).toBe(s1.action_id);
  });

  it('computes a signed batch commitment', () => {
    const log = new WhiteLog('log-test', privateKey);
    log.append(makeSAAE());
    log.append(makeSAAE());
    const batch = log.computeBatch();
    expect(batch.action_count).toBe(2);
    expect(batch.merkle_root).toBeTruthy();
    expect(batch.signature).toBeTruthy();
  });

  it('throws when computing a batch with no new entries', () => {
    const log = new WhiteLog('log-test', privateKey);
    expect(() => log.computeBatch()).toThrow('No new entries');
  });

  it('generates a valid Merkle proof', () => {
    const log = new WhiteLog('log-test', privateKey);
    const s = makeSAAE();
    log.append(s);
    log.append(makeSAAE());
    log.append(makeSAAE());

    const proof = log.getProof(s.action_id);
    expect(proof).toBeDefined();
    expect(log.verifyProof(proof!)).toBe(true);
  });

  it('returns undefined proof for unknown action', () => {
    const log = new WhiteLog('log-test', privateKey);
    expect(log.getProof('nonexistent')).toBeUndefined();
  });

  it('batches only new entries since last batch', () => {
    const log = new WhiteLog('log-test', privateKey);
    log.append(makeSAAE());
    const b1 = log.computeBatch();
    expect(b1.action_count).toBe(1);

    log.append(makeSAAE());
    log.append(makeSAAE());
    const b2 = log.computeBatch();
    expect(b2.action_count).toBe(2);
    expect(log.getBatches()).toHaveLength(2);
  });

  it('filters entries by agent', () => {
    const log = new WhiteLog('log-test', privateKey);
    log.append(makeSAAE('alice'));
    log.append(makeSAAE('bob'));
    log.append(makeSAAE('alice'));
    expect(log.getEntriesForAgent('alice')).toHaveLength(2);
    expect(log.getEntriesForAgent('bob')).toHaveLength(1);
  });
});
