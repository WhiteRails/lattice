/**
 * Legacy single-host MVP: resolves lp:// *.lattice to local ws://127.0.0.1 ports when catalog + resolver have no row.
 * Disabled when {@link LatticeNodeYaml} sets `distributedMesh: true`.
 */
export const LOCAL_FALLBACK_WS_REGISTRY: Record<string, string> = {
  'lp://echo.lattice': 'ws://127.0.0.1:8889',
  'lp://github.lattice': 'ws://127.0.0.1:8890',
  'lp://gmail.lattice': 'ws://127.0.0.1:8891',
  'lp://browser.lattice': 'ws://127.0.0.1:8892',
};
