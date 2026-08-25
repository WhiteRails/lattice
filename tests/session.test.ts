import { describe, expect, it } from 'vitest';
import { generateNodeKeyPair, sessionMaxEntriesFromEnv, SessionManager } from '../node/session';

describe('SessionManager', () => {
  it('validates the process-level ECDH cache budget', () => {
    expect(sessionMaxEntriesFromEnv({ LATTICE_SESSION_MAX_ENTRIES: '128' })).toBe(128);
    expect(() => sessionMaxEntriesFromEnv({ LATTICE_SESSION_MAX_ENTRIES: '3' })).toThrow(/between/i);
    expect(() => sessionMaxEntriesFromEnv({ LATTICE_SESSION_MAX_ENTRIES: 'bad' })).toThrow(/integer/i);
  });

  it('bounds per-peer ECDH cache growth and evicts the least recently used key', () => {
    const local = generateNodeKeyPair();
    const first = generateNodeKeyPair();
    const second = generateNodeKeyPair();
    const manager = new SessionManager('test', local.privateKey, 60_000, 1);

    manager.getSessionKey('first', first.publicKey);
    expect(manager.cachedSessionCount).toBe(1);
    manager.getSessionKey('second', second.publicKey);

    expect(manager.cachedSessionCount).toBe(1);
    expect(manager.hasSession('first')).toBe(false);
    expect(manager.hasSession('second')).toBe(true);
  });

  it('refreshes LRU order without scanning the resident session set', () => {
    const local = generateNodeKeyPair();
    const first = generateNodeKeyPair();
    const second = generateNodeKeyPair();
    const third = generateNodeKeyPair();
    const manager = new SessionManager('test', local.privateKey, 60_000, 2);
    manager.getSessionKey('first', first.publicKey);
    manager.getSessionKey('second', second.publicKey);
    manager.getSessionKey('first', first.publicKey);
    manager.getSessionKey('third', third.publicKey);
    expect(manager.hasSession('first')).toBe(true);
    expect(manager.hasSession('second')).toBe(false);
    expect(manager.hasSession('third')).toBe(true);
  });
});
