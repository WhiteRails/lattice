import { afterEach, describe, expect, it } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { LocalNodeCryptoBackend } from '../node/node-crypto';
import {
  createLinkAuthChallenge,
  createLinkAuthProof,
  verifyLinkAuthChallenge,
  verifyLinkAuthProof,
} from '../node/link-auth';

const dirs: string[] = [];
afterEach(() => dirs.splice(0).forEach(dir => fs.rmSync(dir, { recursive: true, force: true })));

function backend(): LocalNodeCryptoBackend {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lattice-link-auth-'));
  dirs.push(dir);
  return new LocalNodeCryptoBackend(dir);
}

describe('mutual link authentication', () => {
  it('binds both registered identities, roles and a fresh server nonce', async () => {
    const serverBackend = backend();
    const clientBackend = backend();
    const serverKey = await serverBackend.currentKey('identity');
    const clientKey = await clientBackend.currentKey('identity');
    const challenge = await createLinkAuthChallenge('relay-a', serverKey, serverBackend);
    expect(verifyLinkAuthChallenge(challenge, 'relay-a', serverKey)).toEqual(challenge);
    const proof = await createLinkAuthProof(challenge, 'entry-a', 'entry', clientKey, clientBackend);
    expect(verifyLinkAuthProof(proof, challenge, 'entry-a', 'entry', clientKey)).toEqual(proof);
    expect(() => verifyLinkAuthProof(proof, challenge, 'entry-a', 'gateway', clientKey)).toThrow(/mismatch/i);
  });

  it('rejects stale or modified signatures', async () => {
    const serverBackend = backend();
    const serverKey = await serverBackend.currentKey('identity');
    const old = Date.now() - 60_000;
    const stale = await createLinkAuthChallenge('relay-a', serverKey, serverBackend, old);
    expect(() => verifyLinkAuthChallenge(stale, 'relay-a', serverKey)).toThrow(/stale/i);

    const fresh = await createLinkAuthChallenge('relay-a', serverKey, serverBackend);
    const sig = Buffer.from(fresh.signature, 'base64url');
    sig[0] ^= 1;
    expect(() => verifyLinkAuthChallenge({ ...fresh, signature: sig.toString('base64url') }, 'relay-a', serverKey)).toThrow(/signature/i);
  });
});
