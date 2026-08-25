import { describe, expect, it } from 'vitest';
import {
  MAX_GATEWAY_ENDPOINTS_PER_ROUTE,
  normalizeRoutingPayload,
  ROUTING_PAYLOAD_VERSION,
} from '../node/routing-cache';

describe('routing payload data-plane limits', () => {
  const base = {
    version: ROUTING_PAYLOAD_VERSION,
    fqdn: 'echo.lattice',
    gatewayPubKeyB64: 'gateway-key',
  };

  it('rejects endpoint fan-out above the Relay scoring budget', () => {
    expect(() => normalizeRoutingPayload({
      ...base,
      gatewayEndpoints: Array.from({ length: MAX_GATEWAY_ENDPOINTS_PER_ROUTE + 1 }, (_, index) => `wss://gw-${index}.example`),
    })).toThrow(/at most/i);
  });

  it('rejects non-WebSocket endpoints and deduplicates the bounded valid set', () => {
    expect(() => normalizeRoutingPayload({ ...base, gatewayEndpoints: ['https://gateway.example'] }))
      .toThrow(/ws or wss/i);
    expect(normalizeRoutingPayload({
      ...base,
      gatewayEndpoints: [' wss://gateway.example ', 'wss://gateway.example'],
    }).gatewayEndpoints).toEqual(['wss://gateway.example']);
  });
});
