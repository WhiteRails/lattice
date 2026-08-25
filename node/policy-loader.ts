import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';
import { z } from 'zod';
import { LATTICE_DIR, normalizeAgentName } from './state';
import type { TrustedAgentIssuer } from '../core/issuer-trust';
import { BoundedTtlCache } from './bounded-ttl-cache';

export interface PolicyRule { resource: string; actions?: string[]; }
export interface AgentPolicy {
  agent: string;
  /** Ed25519 key allowed to assert this principal across overlay hops. */
  trusted_public_key?: string;
  /** Scalable alternative to distributing one agent public key per Gateway. */
  trusted_issuer?: TrustedAgentIssuer;
  network: { default: 'deny' | 'allow' };
  allow: PolicyRule[];
  deny: PolicyRule[];
  approval_required: PolicyRule[];
}
export interface PolicyCheck { allowed: boolean; requires_approval: boolean; reason: string; }

export const MAX_POLICY_FILE_BYTES = 1 * 1024 * 1024;
export const MAX_POLICY_RULES_PER_SECTION = 256;
export const MAX_POLICY_ACTIONS_PER_RULE = 64;
export const MAX_POLICY_RESOURCE_LENGTH = 2_048;
export const MAX_POLICY_ACTION_LENGTH = 128;
const MISSING_POLICY_WARNING_INTERVAL_MS = 60_000;
const EXPLICIT_POLICY_PRESENCE_TTL_MS = 1_000;

const PolicyRuleSchema = z.object({
  resource: z.string().min(1).max(MAX_POLICY_RESOURCE_LENGTH),
  actions: z.array(z.string().min(1).max(MAX_POLICY_ACTION_LENGTH)).max(MAX_POLICY_ACTIONS_PER_RULE).optional(),
}).strict();

const AgentPolicySchema = z.object({
  agent: z.string(),
  trusted_public_key: z.string().min(32).max(8_192).optional(),
  trusted_issuer: z.object({
    issuer_id: z.string().min(1).max(256),
    public_key: z.string().min(32).max(8_192),
    subject: z.string().min(1).max(512),
  }).strict().optional(),
  network: z.object({ default: z.enum(['deny', 'allow']) }).strict(),
  allow: z.array(PolicyRuleSchema).max(MAX_POLICY_RULES_PER_SECTION),
  deny: z.array(PolicyRuleSchema).max(MAX_POLICY_RULES_PER_SECTION),
  approval_required: z.array(PolicyRuleSchema).max(MAX_POLICY_RULES_PER_SECTION),
}).strict();

export const DEFAULT_POLICY_CACHE_MAX_ENTRIES = 8_192;

export function policyCacheMaxEntriesFromEnv(env: NodeJS.ProcessEnv = process.env): number {
  const raw = env.LATTICE_POLICY_CACHE_MAX_ENTRIES;
  if (raw === undefined || raw.trim() === '') return DEFAULT_POLICY_CACHE_MAX_ENTRIES;
  if (!/^[0-9]+$/.test(raw.trim())) throw new Error('LATTICE_POLICY_CACHE_MAX_ENTRIES must be an integer');
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < 32 || value > 65_536) {
    throw new Error('LATTICE_POLICY_CACHE_MAX_ENTRIES must be between 32 and 65536');
  }
  return value;
}

export class PolicyLoader {
  private dir = path.join(LATTICE_DIR, 'policies');
  private readonly cache = new Map<string, { policy: AgentPolicy; validUntil: number }>();
  private readonly explicitPolicyPresence: BoundedTtlCache<string, boolean>;
  private watcher: fs.FSWatcher | undefined;
  private lastMissingPolicyWarningAt = 0;
  private suppressedMissingPolicyWarnings = 0;

  constructor(private readonly maxCacheEntries = policyCacheMaxEntriesFromEnv()) {
    if (!Number.isSafeInteger(maxCacheEntries) || maxCacheEntries < 1 || maxCacheEntries > 65_536) {
      throw new Error('Policy cache capacity must be between 1 and 65536');
    }
    this.explicitPolicyPresence = new BoundedTtlCache(maxCacheEntries);
    this.ensureWatcher();
  }

  get cachedPolicyCount(): number {
    return this.cache.size;
  }

  get cachedExplicitPolicyPresenceCount(): number {
    return this.explicitPolicyPresence.size;
  }

  /** Distinguishes a deliberate local policy from the default-deny fallback. */
  hasExplicitPolicy(name: string): boolean {
    const canonicalName = normalizeAgentName(name);
    const cached = this.explicitPolicyPresence.get(canonicalName);
    if (cached !== undefined) return cached;
    const exists = fs.existsSync(this.policyPath(canonicalName));
    this.explicitPolicyPresence.set(canonicalName, exists, EXPLICIT_POLICY_PRESENCE_TTL_MS);
    return exists;
  }

  load(name: string): AgentPolicy {
    const canonicalName = normalizeAgentName(name);
    const cached = this.cache.get(canonicalName);
    if (cached && cached.validUntil > Date.now()) {
      this.cache.delete(canonicalName);
      this.cache.set(canonicalName, cached);
      return cached.policy;
    }
    const f = this.policyPath(canonicalName);
    let policy: AgentPolicy;
    if (!fs.existsSync(f)) {
      this.explicitPolicyPresence.set(canonicalName, false, EXPLICIT_POLICY_PRESENCE_TTL_MS);
      this.noteMissingPolicy();
      policy = this.defaultPolicy(canonicalName);
    } else {
      this.explicitPolicyPresence.set(canonicalName, true, EXPLICIT_POLICY_PRESENCE_TTL_MS);
      const bytes = fs.statSync(f).size;
      if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > MAX_POLICY_FILE_BYTES) {
        throw new Error(`Policy file for '${canonicalName}' exceeds ${MAX_POLICY_FILE_BYTES} bytes`);
      }
      const raw = yaml.load(fs.readFileSync(f, 'utf-8'));
      const result = AgentPolicySchema.safeParse(raw);
      if (!result.success) {
        const issue = result.error.issues[0];
        throw new Error(`Policy file for '${canonicalName}' is invalid: ${issue.path.join('.')} - ${issue.message}`);
      }
      if (result.data.agent !== canonicalName) {
        throw new Error(`Policy file principal mismatch for '${canonicalName}'`);
      }
      policy = result.data;
    }
    this.cacheSet(canonicalName, { policy, validUntil: this.watcher ? Number.POSITIVE_INFINITY : Date.now() + 1_000 });
    return policy;
  }

  save(name: string, policy: AgentPolicy): void {
    const canonicalName = normalizeAgentName(name);
    if (policy.agent !== canonicalName) throw new Error('Policy agent must match its canonical filename');
    const result = AgentPolicySchema.safeParse(policy);
    if (!result.success) {
      const issue = result.error.issues[0];
      throw new Error(`Policy for '${canonicalName}' is invalid: ${issue.path.join('.')} - ${issue.message}`);
    }
    if (!fs.existsSync(this.dir)) fs.mkdirSync(this.dir, { recursive: true });
    fs.writeFileSync(this.policyPath(canonicalName), yaml.dump(result.data), { mode: 0o600 });
    this.explicitPolicyPresence.set(canonicalName, true, EXPLICIT_POLICY_PRESENCE_TTL_MS);
    this.ensureWatcher();
    this.cacheSet(canonicalName, { policy: result.data, validUntil: this.watcher ? Number.POSITIVE_INFINITY : Date.now() + 1_000 });
  }

  pinAgentPublicKey(name: string, publicKey: string): void {
    const p = this.load(name);
    p.trusted_public_key = publicKey;
    this.save(name, p);
  }

  trustAgentIssuer(name: string, trust: TrustedAgentIssuer): void {
    const p = this.load(name);
    p.trusted_issuer = trust;
    this.save(name, p);
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

  /** Allows long-running Gateway instances to release their directory watcher. */
  dispose(): void {
    this.watcher?.close();
    this.watcher = undefined;
    this.cache.clear();
    this.explicitPolicyPresence.clear();
  }

  private ensureWatcher(): void {
    if (this.watcher || !fs.existsSync(this.dir)) return;
    try {
      this.watcher = fs.watch(this.dir, { persistent: false }, () => {
        // A policy file can affect more than one cache key through deletion or
        // replacement. Clear atomically rather than trusting event filenames.
        this.cache.clear();
        this.explicitPolicyPresence.clear();
      });
      this.watcher.on('error', () => {
        this.watcher?.close();
        this.watcher = undefined;
        this.cache.clear();
        this.explicitPolicyPresence.clear();
      });
    } catch {
      // Filesystems without watch support retain only a short cache, preserving
      // a bounded propagation delay instead of stale policy.
      this.watcher = undefined;
    }
  }

  private cacheSet(name: string, entry: { policy: AgentPolicy; validUntil: number }): void {
    this.cache.delete(name);
    while (this.cache.size >= this.maxCacheEntries) {
      const oldest = this.cache.keys().next().value as string | undefined;
      if (!oldest) break;
      this.cache.delete(oldest);
    }
    this.cache.set(name, entry);
  }

  /**
   * An unauthenticated peer can name arbitrary agents. Keep the operational
   * signal, but never emit an attacker-selected identity or one line per miss.
   */
  private noteMissingPolicy(): void {
    const now = Date.now();
    if (now - this.lastMissingPolicyWarningAt < MISSING_POLICY_WARNING_INTERVAL_MS) {
      this.suppressedMissingPolicyWarnings++;
      return;
    }
    console.warn(JSON.stringify({
      level: 'WARN',
      event: 'default_policy_activated',
      reason: 'policy_file_missing',
      policy: 'default-deny+internet-blocked',
      suppressed: this.suppressedMissingPolicyWarnings,
    }));
    this.lastMissingPolicyWarningAt = now;
    this.suppressedMissingPolicyWarnings = 0;
  }

  private match(pattern: string, resource: string): boolean {
    if (pattern === '*') return true;
    if (pattern === resource) return true;
    if (pattern === 'internet:*') return !resource.startsWith('lp://');
    if (pattern.endsWith(':*')) return resource.startsWith(pattern.slice(0, -1));
    if (pattern.endsWith('*')) return resource.startsWith(pattern.slice(0, -1));
    return false;
  }

  private defaultPolicy(name: string): AgentPolicy {
    return { agent: name, network: { default: 'deny' }, allow: [], deny: [{ resource: 'internet:*' }], approval_required: [] };
  }

  private policyPath(name: string) {
    const canonical = normalizeAgentName(name);
    const base = path.resolve(this.dir);
    const candidate = path.resolve(base, `${canonical}.yaml`);
    if (!candidate.startsWith(base + path.sep)) throw new Error('Policy path escaped policy directory');
    return candidate;
  }
}
