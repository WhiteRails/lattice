import { describe, expect, it } from 'vitest';
import * as crypto from 'crypto';
import {
  answerNtorV3,
  createNtorV3Client,
  finishNtorV3,
  generateRawX25519KeyPair,
  ntorNodeId,
} from '../node/onion-handshake';

function identityPublicKey(): string {
  return crypto.generateKeyPairSync('ed25519', {
    publicKeyEncoding: { format: 'der', type: 'spki' },
    privateKeyEncoding: { format: 'der', type: 'pkcs8' },
  }).publicKey.toString('base64');
}

describe('Lattice ntor-v3 handshake', () => {
  it('derives identical directional keys from independent ephemeral material', () => {
    const onion = generateRawX25519KeyPair();
    const nodeId = ntorNodeId(identityPublicKey());
    const client = createNtorV3Client(nodeId, onion.publicKey);
    const server = answerNtorV3(client.create, nodeId, onion);
    const clientKeys = finishNtorV3(client, server.created);

    expect(clientKeys.forwardKey.equals(server.keys.forwardKey)).toBe(true);
    expect(clientKeys.backwardKey.equals(server.keys.backwardKey)).toBe(true);
    expect(clientKeys.forwardNonceSalt.equals(server.keys.forwardNonceSalt)).toBe(true);
    expect(clientKeys.backwardNonceSalt.equals(server.keys.backwardNonceSalt)).toBe(true);
    expect(clientKeys.forwardKey.equals(clientKeys.backwardKey)).toBe(false);
  });

  it('rejects identity, onion key, client MAC and server authentication tampering', () => {
    const onion = generateRawX25519KeyPair();
    const nodeId = ntorNodeId(identityPublicKey());
    const client = createNtorV3Client(nodeId, onion.publicKey);
    expect(() => answerNtorV3(client.create, '00'.repeat(32), onion)).toThrow(/identity/i);
    expect(() => answerNtorV3(client.create, nodeId, generateRawX25519KeyPair())).toThrow(/onion key/i);

    const badMac = { ...client.create, extensions_mac: 'AA'.repeat(16) };
    expect(() => answerNtorV3(badMac, nodeId, onion)).toThrow();

    const server = answerNtorV3(client.create, nodeId, onion);
    const auth = Buffer.from(server.created.auth, 'base64url');
    auth[0] ^= 1;
    expect(() => finishNtorV3(client, { ...server.created, auth: auth.toString('base64url') })).toThrow(/authentication/i);
  });
});
