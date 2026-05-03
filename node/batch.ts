import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { tailLog, WHITENET_DIR } from './state';
import { merkleRoot, merkleProofPath, MerkleProof } from '../core/log';

export interface BatchMetadata {
  batch_id: string;
  merkle_root: string;
  from_timestamp: string;
  to_timestamp: string;
  action_count: number;
  created_at: string;
  actions: string[]; // action_ids included
}

export function createBatch(): BatchMetadata {
  const actions = tailLog(10000); // For MVP, grab recent unbatched
  if (actions.length === 0) throw new Error("No actions to batch");

  const batchDir = path.join(WHITENET_DIR, 'batches');
  if (!fs.existsSync(batchDir)) fs.mkdirSync(batchDir, { recursive: true });

  // Only take actions not already in a batch (naive approach for MVP: read all batches and exclude)
  const existingBatches = fs.readdirSync(batchDir).filter(f => f.endsWith('.json'));
  const batchedActionIds = new Set<string>();
  for (const b of existingBatches) {
    const meta: BatchMetadata = JSON.parse(fs.readFileSync(path.join(batchDir, b), 'utf-8'));
    meta.actions.forEach(a => batchedActionIds.add(a));
  }

  const unbatched = actions.filter((a: any) => a.action_id && !batchedActionIds.has(a.action_id));
  if (unbatched.length === 0) throw new Error("No new actions to batch");

  // To build Merkle Tree, we need leaf hashes. We'll hash the JSON string of each action for the MVP.
  // In a real system, we'd use the envelope hash.
  const leaves = unbatched.map(a => crypto.createHash('sha256').update(JSON.stringify(a)).digest('hex'));
  const root = merkleRoot(leaves);

  const batch_id = `batch_${crypto.randomBytes(6).toString('hex')}`;
  const fromTs = (unbatched[0] as any).timestamp;
  const toTs = (unbatched[unbatched.length - 1] as any).timestamp;
  const meta: BatchMetadata = {
    batch_id,
    merkle_root: '0x' + root,
    from_timestamp: fromTs,
    to_timestamp: toTs,
    action_count: unbatched.length,
    created_at: new Date().toISOString(),
    actions: unbatched.map((a: any) => a.action_id)
  };

  fs.writeFileSync(path.join(batchDir, `${batch_id}.json`), JSON.stringify(meta, null, 2));
  return meta;
}

export function generateProof(actionId: string): { batch: BatchMetadata, proof: MerkleProof } {
  const batchDir = path.join(WHITENET_DIR, 'batches');
  if (!fs.existsSync(batchDir)) throw new Error("No batches found");

  const existingBatches = fs.readdirSync(batchDir).filter(f => f.endsWith('.json'));
  let targetBatch: BatchMetadata | undefined;
  
  for (const b of existingBatches) {
    const meta: BatchMetadata = JSON.parse(fs.readFileSync(path.join(batchDir, b), 'utf-8'));
    if (meta.actions.includes(actionId)) {
      targetBatch = meta;
      break;
    }
  }

  if (!targetBatch) throw new Error(`Action ${actionId} not found in any batch`);

  // Reconstruct leaves to get the path
  const actions = tailLog(10000);
  const batchActions = actions.filter((a: any) => targetBatch!.actions.includes(a.action_id));
  const leaves = batchActions.map(a => crypto.createHash('sha256').update(JSON.stringify(a)).digest('hex'));
  
  const idx = targetBatch.actions.indexOf(actionId);
  const pathArr = merkleProofPath(leaves, idx);

  return {
    batch: targetBatch,
    proof: {
      action_id: actionId,
      leaf_hash: leaves[idx],
      path: pathArr,
      root: targetBatch.merkle_root.replace('0x', '')
    }
  };
}
