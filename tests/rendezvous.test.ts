import { describe, expect, it } from 'vitest';
import { FEDERATION_ROUTE_REPLICATION, federationReplicaUrls, rendezvousOrder } from '../node/rendezvous';

describe('rendezvousOrder', () => {
  const gateways = ['wss://gw-a.example', 'wss://gw-b.example', 'wss://gw-c.example', 'wss://gw-d.example'];

  it('is deterministic, deduplicates endpoints, and produces a complete failover order', () => {
    const key = 'echo.lattice\u0000agent-42';
    expect(rendezvousOrder([...gateways, gateways[0]!], key)).toEqual(rendezvousOrder(gateways, key));
    expect(rendezvousOrder(gateways, key)).toHaveLength(gateways.length);
    expect(new Set(rendezvousOrder(gateways, key))).toEqual(new Set(gateways));
  });

  it('distributes independent agents across replicas without a shared assignment table', () => {
    const counts = new Map(gateways.map(gateway => [gateway, 0]));
    for (let index = 0; index < 4_000; index++) {
      const winner = rendezvousOrder(gateways, `echo.lattice\u0000agent-${index}`)[0]!;
      counts.set(winner, counts.get(winner)! + 1);
    }
    // A deliberately broad interval avoids treating a statistical property as
    // a benchmark while detecting a broken/single-winner implementation.
    for (const count of counts.values()) {
      expect(count).toBeGreaterThan(700);
      expect(count).toBeLessThan(1_300);
    }
  });

  it('keeps the current winner when an unrelated replica is added', () => {
    const key = 'echo.lattice\u0000agent-sticky';
    const before = rendezvousOrder(gateways, key)[0]!;
    const after = rendezvousOrder([...gateways, 'wss://gw-new.example'], key)[0]!;
    expect([before, 'wss://gw-new.example']).toContain(after);
  });

  it('selects a fixed, deterministic and bounded federation replica set per name', () => {
    const registries = Array.from({ length: 20 }, (_, index) => `https://registry-${index}.example`);
    const first = federationReplicaUrls(registries, 'echo.lattice');
    expect(first).toEqual(federationReplicaUrls([...registries].reverse(), 'echo.lattice'));
    expect(first).toHaveLength(FEDERATION_ROUTE_REPLICATION);
    expect(new Set(first).size).toBe(FEDERATION_ROUTE_REPLICATION);
    expect(federationReplicaUrls(registries.slice(0, 2), 'echo.lattice')).toHaveLength(2);
  });
});
