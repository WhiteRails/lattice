import * as crypto from 'crypto';
import type { OverlayMessage } from './message';
import type { LatticeNodeRole, LatticeNodeYaml, NodeChainConfig } from './node-config';
import { chainGetLatticeNode, type ChainLatticeNodeRecord } from './chain';
import { readRoutingCacheFile } from './routing-cache';

export const NODE_ROLE_BITS: Record<LatticeNodeRole, number> = {
  entry: 1,
  relay: 2,
  gateway: 4,
};
const NODE_LABEL_RE = /^[a-z0-9._-]{1,64}$/;
const OVERLAY_PUBKEY_RE = /^[A-Za-z0-9+/]{59}=$/;

export function roleBitmaskFromRoles(roles: LatticeNodeRole[]): number {
  return roles.reduce((acc, role) => acc | NODE_ROLE_BITS[role], 0);
}

export function overlayPubkeysEqual(a?: string, b?: string): boolean {
  if (!a || !b) return false;
  try {
    if (!OVERLAY_PUBKEY_RE.test(a) || !OVERLAY_PUBKEY_RE.test(b)) return false;
    const ba = Buffer.from(a.trim(), 'base64');
    const bb = Buffer.from(b.trim(), 'base64');
    if (ba.length !== 44 || bb.length !== 44) return false;
    return crypto.timingSafeEqual(ba, bb);
  } catch {
    return false;
  }
}

export async function resolveRegisteredNode(
  cfg: LatticeNodeYaml | null,
  chain: NodeChainConfig | null,
  label: string,
): Promise<ChainLatticeNodeRecord | null> {
  if (chain) return chainGetLatticeNode(chain.rpcUrl, chain.contractAddress, label);
  const row = readRoutingCacheFile(cfg, { requireLocalSig: true })?.latticeNodes[label];
  if (!row) return null;
  return {
    overlayPubKeyB64: row.overlayPubKeyB64,
    identityPubKeyB64: row.identityPubKeyB64 ?? '',
    onionPubKeyB64Url: row.onionPubKeyB64Url ?? '',
    tlsFingerprintSha256: row.tlsFingerprintSha256 ?? '',
    operatorId: row.operatorId ?? '',
    roleBitmask: row.roleBitmask ?? 0,
    active: true,
  };
}

export async function validateDistributedPeer(opts: {
  distributedMesh: boolean;
  cfg: LatticeNodeYaml | null;
  chain: NodeChainConfig | null;
  msg: OverlayMessage;
  expectedRole: LatticeNodeRole;
  expectedLabel?: string;
  expectedPubKeyB64?: string;
}): Promise<{
  ok: true;
  label?: string;
  pubkey?: string;
  identityPubKeyB64?: string;
  onionPubKeyB64Url?: string;
  operatorId?: string;
  tlsFingerprintSha256?: string;
} | { ok: false; error: string }> {
  if (!opts.distributedMesh) return { ok: true };

  const label = opts.msg.source_node_label?.trim();
  const role = opts.msg.source_node_role;
  const pubkey = opts.msg.source_pubkey?.trim();

  if (!label || !NODE_LABEL_RE.test(label)) return { ok: false, error: `Invalid source_node_label for ${opts.expectedRole} peer` };
  if (!role) return { ok: false, error: `Missing source_node_role for ${label}` };
  if (role !== opts.expectedRole) return { ok: false, error: `Unexpected node role for ${label}: ${role}` };
  if (!pubkey || !OVERLAY_PUBKEY_RE.test(pubkey)) return { ok: false, error: `Invalid source_pubkey for ${label}` };
  if (opts.expectedLabel && label !== opts.expectedLabel) {
    return { ok: false, error: `Unexpected node label: ${label} (expected ${opts.expectedLabel})` };
  }
  if (opts.expectedPubKeyB64 && !overlayPubkeysEqual(pubkey, opts.expectedPubKeyB64)) {
    return { ok: false, error: `Peer pubkey mismatch for ${label}` };
  }

  let rec: ChainLatticeNodeRecord | null;
  try {
    rec = await resolveRegisteredNode(opts.cfg, opts.chain, label);
  } catch {
    return { ok: false, error: `Unable to resolve lattice node: ${label}` };
  }
  if (!rec) return { ok: false, error: `Unregistered lattice node: ${label}` };
  if (!rec.active) return { ok: false, error: `Inactive lattice node: ${label}` };
  if ((rec.roleBitmask & NODE_ROLE_BITS[opts.expectedRole]) === 0) {
    return { ok: false, error: `Registered node ${label} lacks role ${opts.expectedRole}` };
  }
  if (!overlayPubkeysEqual(pubkey, rec.overlayPubKeyB64)) {
    return { ok: false, error: `Registered pubkey mismatch for ${label}` };
  }

  return {
    ok: true,
    label,
    pubkey,
    identityPubKeyB64: rec.identityPubKeyB64,
    onionPubKeyB64Url: rec.onionPubKeyB64Url,
    operatorId: rec.operatorId,
    tlsFingerprintSha256: rec.tlsFingerprintSha256,
  };
}
