import * as http from 'http';
import { serviceExists, loadService, isRevoked } from './state';
import { PolicyLoader } from './policy-loader';

export interface PingResult {
  address: string;
  resolved: boolean;
  cert_status: 'valid' | 'not_found' | 'revoked';
  revocation: 'fresh' | 'unknown';
  latency_ms: number;
  reachable: boolean;
  agent?: string;
  actions_allowed: string[];
  actions_blocked: string[];
}

// Known actions per service for policy display
const SERVICE_ACTIONS: Record<string, string[]> = {
  echo:    ['echo.ping'],
  github:  ['repo.read', 'issue.create', 'repo.delete', 'secret.read'],
  gmail:   ['email.draft', 'email.send', 'email.mass'],
  stripe:  ['invoice.draft', 'payment.execute'],
  browser: ['web.read', 'web.post', 'web.download'],
};

export async function ping(address: string, agentName?: string): Promise<PingResult> {
  const svcName = address.replace('lp://', '').replace('.lattice', '');
  const start = Date.now();

  const result: PingResult = {
    address, resolved: false, cert_status: 'not_found',
    revocation: 'unknown', latency_ms: 0, reachable: false,
    agent: agentName, actions_allowed: [], actions_blocked: [],
  };

  if (!serviceExists(svcName)) {
    result.latency_ms = Date.now() - start;
    return result;
  }

  result.resolved = true;
  result.cert_status = 'valid';
  result.revocation = 'fresh';

  // Policy check per action
  if (agentName) {
    const pl = new PolicyLoader();
    for (const action of SERVICE_ACTIONS[svcName] ?? []) {
      const c = pl.check(agentName, address, action);
      if (c.allowed && !c.requires_approval) result.actions_allowed.push(action);
      else if (c.allowed && c.requires_approval) result.actions_blocked.push(`${action} (approval required)`);
      else result.actions_blocked.push(action);
    }
  }

  // Probe latency
  const svc = loadService(svcName);
  try {
    await probe(svc.url);
    result.reachable = true;
  } catch { result.reachable = false; }

  result.latency_ms = Date.now() - start;
  return result;
}

function probe(url: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const req = http.get(url + '/ping', { timeout: 3000 }, r => { r.resume(); resolve(); });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
  });
}
