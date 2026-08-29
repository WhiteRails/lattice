import type * as http from 'http';

export interface CellMetricSnapshot {
  inFlight: number;
  inFlightBytes: number;
  rejected: number;
  maxInFlight: number;
  maxInFlightBytes: number;
  outboundInFlight?: number;
  residentPeers?: number;
  failures?: number;
  issuerCertificateCacheEntries?: number;
  issuerCertificateCacheHits?: number;
  issuerCertificateCacheMisses?: number;
  onionCircuitsActive?: number;
  onionCircuitsBuilt?: number;
  onionCircuitsDestroyed?: number;
  onionNtorFailures?: number;
  onionReplayFailures?: number;
  onionInvalidTags?: number;
  hpkeFailures?: number;
  tlsPinMismatches?: number;
  onionPaddingBytes?: number;
}

/**
 * Minimal bounded-cardinality Prometheus surface for a Lattice cell role.
 * It intentionally carries no principal, route, nonce, or endpoint label.
 */
export function serveCellStatus(
  req: http.IncomingMessage,
  res: http.ServerResponse,
  role: 'entry' | 'relay' | 'gateway',
  snapshot: () => CellMetricSnapshot,
): boolean {
  const pathname = (req.url ?? '/').split('?')[0];
  if (req.method !== 'GET' || (pathname !== '/healthz' && pathname !== '/metrics')) return false;
  const data = snapshot();
  if (pathname === '/healthz') {
    res.writeHead(200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    res.end(JSON.stringify({ ok: true, role, inFlight: data.inFlight, rejected: data.rejected }));
    return true;
  }
  const labels = `{role="${role}"}`;
  const fields: Array<[string, number | undefined]> = [
    ['lattice_overlay_inflight', data.inFlight],
    ['lattice_overlay_inflight_bytes', data.inFlightBytes],
    ['lattice_overlay_rejected_total', data.rejected],
    ['lattice_overlay_inflight_limit', data.maxInFlight],
    ['lattice_overlay_inflight_bytes_limit', data.maxInFlightBytes],
    ['lattice_overlay_outbound_inflight', data.outboundInFlight],
    ['lattice_overlay_resident_peers', data.residentPeers],
    ['lattice_overlay_failures_total', data.failures],
    ['lattice_issuer_certificate_cache_entries', data.issuerCertificateCacheEntries],
    ['lattice_issuer_certificate_cache_hits_total', data.issuerCertificateCacheHits],
    ['lattice_issuer_certificate_cache_misses_total', data.issuerCertificateCacheMisses],
    ['lattice_onion_circuits_active', data.onionCircuitsActive],
    ['lattice_onion_circuits_built_total', data.onionCircuitsBuilt],
    ['lattice_onion_circuits_destroyed_total', data.onionCircuitsDestroyed],
    ['lattice_onion_ntor_failures_total', data.onionNtorFailures],
    ['lattice_onion_replay_failures_total', data.onionReplayFailures],
    ['lattice_onion_invalid_tags_total', data.onionInvalidTags],
    ['lattice_hpke_failures_total', data.hpkeFailures],
    ['lattice_tls_pin_mismatches_total', data.tlsPinMismatches],
    ['lattice_onion_padding_bytes_total', data.onionPaddingBytes],
  ];
  const body = [
    '# HELP lattice_overlay_inflight Current admitted overlay work in this process.',
    '# TYPE lattice_overlay_inflight gauge',
    ...fields
      .filter((entry): entry is [string, number] => Number.isFinite(entry[1]))
      .map(([name, value]) => `${name}${labels} ${value}`),
    '',
  ].join('\n');
  res.writeHead(200, {
    'content-type': 'text/plain; version=0.0.4; charset=utf-8',
    'cache-control': 'no-store',
  });
  res.end(body);
  return true;
}
