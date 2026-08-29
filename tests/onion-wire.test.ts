import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { afterEach, describe, expect, it } from 'vitest';
import { LocalNodeCryptoBackend } from '../node/node-crypto';
import { createNtorV3Client, ntorNodeId } from '../node/onion-handshake';
import {
  createAuthenticatedOnionCreate2,
  verifyAuthenticatedOnionCreate2,
} from '../node/onion-wire';

const dirs: string[] = [];
afterEach(() => dirs.splice(0).forEach(dir => fs.rmSync(dir, { recursive: true, force: true })));

describe('binary CREATE2 link authentication', () => {
  it('binds circuit, role, nonce and ntor transcript to the registered Ed25519 identity', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lattice-create2-auth-'));
    dirs.push(dir);
    const backend = new LocalNodeCryptoBackend(path.join(dir, 'keys'));
    const [identity, onion] = await backend.ensureKeys(['identity', 'onion']);
    const ntor = createNtorV3Client(ntorNodeId(identity.publicKey), onion.publicKey);
    const now = Date.now();
    const proof = await createAuthenticatedOnionCreate2(
      123, 0, 'entry-a', 'entry', ntor.create, identity, backend, now,
    );
    expect(verifyAuthenticatedOnionCreate2(proof, 123, 'entry-a', 'entry', identity, now)).toMatchObject({
      circuit_id: 123,
      client_label: 'entry-a',
    });
    expect(() => verifyAuthenticatedOnionCreate2(proof, 124, 'entry-a', 'entry', identity, now)).toThrow(/mismatch/);
    expect(() => verifyAuthenticatedOnionCreate2({ ...proof, hop_index: 1 }, 123, 'entry-a', 'entry', identity, now)).toThrow(/signature/);
    expect(() => verifyAuthenticatedOnionCreate2(proof, 123, 'entry-a', 'entry', identity, now + 30_001)).toThrow(/stale/i);
  });
});
