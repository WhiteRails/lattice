import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';
import { LATTICE_DIR } from './state';

export interface PolicyRule { resource: string; actions?: string[]; }
export interface AgentPolicy {
  agent: string;
  network: { default: 'deny' | 'allow' };
  allow: PolicyRule[];
  deny: PolicyRule[];
  approval_required: PolicyRule[];
}
export interface PolicyCheck { allowed: boolean; requires_approval: boolean; reason: string; }

export class PolicyLoader {
  private dir = path.join(LATTICE_DIR, 'policies');

  load(name: string): AgentPolicy {
    const f = this.policyPath(name);
    if (!fs.existsSync(f)) return this.defaultPolicy(name);
    return yaml.load(fs.readFileSync(f, 'utf-8')) as AgentPolicy;
  }

  save(name: string, policy: AgentPolicy): void {
    if (!fs.existsSync(this.dir)) fs.mkdirSync(this.dir, { recursive: true });
    fs.writeFileSync(this.policyPath(name), yaml.dump(policy));
  }

  grant(name: string, resource: string, actions: string[]): void {
    const p = this.load(name);
    const ex = p.allow.find(r => r.resource === resource);
    if (ex) ex.actions = [...new Set([...(ex.actions ?? []), ...actions])];
    else p.allow.push({ resource, actions });
    this.save(name, p);
  }

  deny(name: string, resource: string): void {
    const p = this.load(name);
    if (!p.deny.find(r => r.resource === resource)) p.deny.push({ resource });
    this.save(name, p);
  }

  requireApproval(name: string, resource: string, actions: string[]): void {
    const p = this.load(name);
    const ex = p.approval_required.find(r => r.resource === resource);
    if (ex) ex.actions = [...new Set([...(ex.actions ?? []), ...actions])];
    else p.approval_required.push({ resource, actions });
    this.save(name, p);
  }

  check(name: string, resource: string, action: string): PolicyCheck {
    const p = this.load(name);
    for (const r of p.deny)
      if (this.match(r.resource, resource))
        return { allowed: false, requires_approval: false, reason: `Denied: ${r.resource}` };

    for (const r of p.approval_required)
      if (this.match(r.resource, resource) && (!r.actions || r.actions.includes(action)))
        return { allowed: true, requires_approval: true, reason: `${action} on ${resource} requires approval` };

    for (const r of p.allow)
      if (this.match(r.resource, resource)) {
        if (!r.actions || r.actions.includes(action))
          return { allowed: true, requires_approval: false, reason: `Allowed: ${r.resource}` };
        return { allowed: false, requires_approval: false, reason: `Action '${action}' not in allowed list for ${resource}` };
      }

    const def = p.network?.default === 'allow';
    return { allowed: def, requires_approval: false, reason: def ? 'Default allow' : 'Default deny' };
  }

  inspect(name: string): string {
    const p = this.load(name);
    const lines = [`agent: ${p.agent}`, `default: ${p.network?.default ?? 'deny'}`, '', 'allow:'];
    for (const r of p.allow) { lines.push(`  ${r.resource}`); (r.actions ?? []).forEach(a => lines.push(`    - ${a}`)); }
    lines.push('', 'deny:');
    for (const r of p.deny) lines.push(`  ${r.resource}`);
    lines.push('', 'approval_required:');
    for (const r of p.approval_required) { lines.push(`  ${r.resource}`); (r.actions ?? []).forEach(a => lines.push(`    - ${a}`)); }
    return lines.join('\n');
  }

  private match(pattern: string, resource: string): boolean {
    if (pattern === resource) return true;
    if (pattern === 'internet:*') return !resource.startsWith('lp://');
    if (pattern.endsWith(':*')) return resource.startsWith(pattern.slice(0, -2));
    return false;
  }

  private defaultPolicy(name: string): AgentPolicy {
    return { agent: name, network: { default: 'deny' }, allow: [], deny: [{ resource: 'internet:*' }], approval_required: [] };
  }

  private policyPath(name: string) { return path.join(this.dir, `${name}.yaml`); }
}
