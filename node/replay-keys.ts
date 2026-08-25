/**
 * Replay claims are shared within a replicated trust boundary, not across
 * different verification stages. Entry and Gateway intentionally verify the
 * same signed request, so they require separate namespaces in one Redis cell.
 */
export function entryReplayKey(agent: string, timestamp: string, nonce: string): string {
  return `entry:${agent}:${timestamp}:${nonce}`;
}

export function gatewayReplayKey(agent: string, timestamp: string, nonce: string): string {
  return `gateway:${agent}:${timestamp}:${nonce}`;
}
