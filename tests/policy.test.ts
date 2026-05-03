import { describe, it, expect } from 'vitest';
import { WhitePolicy } from '../core/policy';

describe('WhitePolicy', () => {
  it('grants and allows a low-risk capability', () => {
    const p = new WhitePolicy();
    p.grantCapability({
      agent_id: 'agent-1',
      tool_id: 'search.query',
      capability_class: 'read:public',
      granted_by: 'human-1',
    });

    const d = p.evaluate({ agent_id: 'agent-1', tool_id: 'search.query', capability_class: 'read:public', pas_score: 0 });
    expect(d.decision).toBe('allow');
    expect(d.risk_level).toBe(0);
  });

  it('denies when no grant exists', () => {
    const p = new WhitePolicy();
    const d = p.evaluate({ agent_id: 'agent-1', tool_id: 'gmail.send', capability_class: 'message:single', pas_score: 0 });
    expect(d.decision).toBe('deny');
  });

  it('requires human approval for high-risk capability class', () => {
    const p = new WhitePolicy();
    p.grantCapability({
      agent_id: 'agent-1',
      tool_id: 'aws.provision',
      capability_class: 'cloud:provision',
      granted_by: 'human-1',
    });

    const d = p.evaluate({ agent_id: 'agent-1', tool_id: 'aws.provision', capability_class: 'cloud:provision', pas_score: 0 });
    expect(d.decision).toBe('require_human_approval');
    expect(d.risk_level).toBe(4);
  });

  it('requires human approval when grant flag is set', () => {
    const p = new WhitePolicy();
    p.grantCapability({
      agent_id: 'agent-1',
      tool_id: 'email.send',
      capability_class: 'message:single',
      granted_by: 'human-1',
      requires_human_approval: true,
    });

    const d = p.evaluate({ agent_id: 'agent-1', tool_id: 'email.send', capability_class: 'message:single', pas_score: 0 });
    expect(d.decision).toBe('require_human_approval');
  });

  it('escalates to require_human_approval when PAS exceeds threshold', () => {
    const p = new WhitePolicy();
    p.grantCapability({
      agent_id: 'agent-1',
      tool_id: 'search.query',
      capability_class: 'read:public',
      granted_by: 'human-1',
    });

    const d = p.evaluate({ agent_id: 'agent-1', tool_id: 'search.query', capability_class: 'read:public', pas_score: 105 });
    expect(d.decision).toBe('require_human_approval');
  });

  it('escalates to pause_agent when PAS is critically high', () => {
    const p = new WhitePolicy();
    p.grantCapability({
      agent_id: 'agent-1',
      tool_id: 'search.query',
      capability_class: 'read:public',
      granted_by: 'human-1',
    });

    const d = p.evaluate({ agent_id: 'agent-1', tool_id: 'search.query', capability_class: 'read:public', pas_score: 250 });
    expect(d.decision).toBe('pause_agent');
  });

  it('denies after max_uses is exhausted', () => {
    const p = new WhitePolicy();
    p.grantCapability({
      agent_id: 'agent-1',
      tool_id: 'tool.a',
      capability_class: 'read:private',
      granted_by: 'human-1',
      max_uses: 2,
    });

    p.evaluate({ agent_id: 'agent-1', tool_id: 'tool.a', capability_class: 'read:private', pas_score: 0 });
    p.evaluate({ agent_id: 'agent-1', tool_id: 'tool.a', capability_class: 'read:private', pas_score: 0 });
    const d = p.evaluate({ agent_id: 'agent-1', tool_id: 'tool.a', capability_class: 'read:private', pas_score: 0 });
    expect(d.decision).toBe('deny');
  });

  it('revokes a grant and subsequent calls are denied', () => {
    const p = new WhitePolicy();
    const grant = p.grantCapability({
      agent_id: 'agent-1',
      tool_id: 'tool.b',
      capability_class: 'read:public',
      granted_by: 'human-1',
    });

    p.revokeGrant(grant.grant_id);
    const d = p.evaluate({ agent_id: 'agent-1', tool_id: 'tool.b', capability_class: 'read:public', pas_score: 0 });
    expect(d.decision).toBe('deny');
  });

  it('getRiskLevel returns correct values', () => {
    const p = new WhitePolicy();
    expect(p.getRiskLevel('read:public')).toBe(0);
    expect(p.getRiskLevel('money:execute')).toBe(5);
    expect(p.getRiskLevel('physical:operate')).toBe(5);
    expect(p.getRiskLevel('unknown:class')).toBe(3); // default
  });
});
