/**
 * Process-level network admission budgets.
 *
 * Message admission protects CPU and retained payloads after a request reaches
 * a role.  These bounds protect the earlier, cheaper resource: file
 * descriptors and sockets held by slow or idle peers.  They are intentionally
 * shared by Entry, Relay and Gateway so a cell has one obvious capacity knob.
 */
export interface InboundNetworkLimits {
  maxConnections: number;
  headersTimeoutMs: number;
  requestTimeoutMs: number;
  websocketIdleTimeoutMs: number;
}

export const DEFAULT_INBOUND_NETWORK_LIMITS: InboundNetworkLimits = {
  maxConnections: 8_192,
  headersTimeoutMs: 15_000,
  requestTimeoutMs: 60_000,
  websocketIdleTimeoutMs: 120_000,
};

function boundedInteger(
  value: string | undefined,
  fallback: number,
  min: number,
  max: number,
  name: string,
): number {
  if (value === undefined || value.trim() === '') return fallback;
  if (!/^[0-9]+$/.test(value.trim())) throw new Error(`${name} must be an integer`);
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < min || parsed > max) {
    throw new Error(`${name} must be between ${min} and ${max}`);
  }
  return parsed;
}

/** Parse once during role startup; invalid capacity configuration fails closed. */
export function inboundNetworkLimitsFromEnv(env: NodeJS.ProcessEnv = process.env): InboundNetworkLimits {
  return {
    maxConnections: boundedInteger(
      env.LATTICE_MAX_INBOUND_CONNECTIONS,
      DEFAULT_INBOUND_NETWORK_LIMITS.maxConnections,
      64,
      131_072,
      'LATTICE_MAX_INBOUND_CONNECTIONS',
    ),
    headersTimeoutMs: boundedInteger(
      env.LATTICE_HTTP_HEADERS_TIMEOUT_MS,
      DEFAULT_INBOUND_NETWORK_LIMITS.headersTimeoutMs,
      1_000,
      120_000,
      'LATTICE_HTTP_HEADERS_TIMEOUT_MS',
    ),
    requestTimeoutMs: boundedInteger(
      env.LATTICE_HTTP_REQUEST_TIMEOUT_MS,
      DEFAULT_INBOUND_NETWORK_LIMITS.requestTimeoutMs,
      1_000,
      600_000,
      'LATTICE_HTTP_REQUEST_TIMEOUT_MS',
    ),
    websocketIdleTimeoutMs: boundedInteger(
      env.LATTICE_WEBSOCKET_IDLE_TIMEOUT_MS,
      DEFAULT_INBOUND_NETWORK_LIMITS.websocketIdleTimeoutMs,
      1_000,
      3_600_000,
      'LATTICE_WEBSOCKET_IDLE_TIMEOUT_MS',
    ),
  };
}
