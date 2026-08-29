import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { describe, expect, it } from 'vitest';
import {
  gatewayResponseSignaturePayload,
  parseE2eRequest,
  parseE2eResponse,
  verifyGatewayResponse,
  type E2eResponseUnsigned,
} from '../node/e2e-message';
import { generateHpkeKeyPair, openHpkeJson, sealHpkeJson } from '../node/hpke-envelope';
import { LocalNodeCryptoBackend } from '../node/node-crypto';

describe('Entry/Gateway end-to-end messages', () => {
  it('relays see only an opaque HPKE envelope and Entry verifies the Gateway identity signature', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lattice-e2e-'));
    const backend = new LocalNodeCryptoBackend(path.join(dir, 'keys'));
    const [identity, gatewayEncryption] = await backend.ensureKeys(['identity', 'gateway-encryption']);
    const responseKey = await generateHpkeKeyPair();
    const requestId = '11'.repeat(16);
    const routeHash = `0x${'22'.repeat(32)}`;
    const createdAt = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 60_000).toISOString();
    const secretRequest = {
      version: 1,
      request_id: requestId,
      route_hash: routeHash,
      source: 'private-agent',
      destination: 'lp://secret.lattice',
      method: 'POST',
      url: '/private/path',
      headers: { authorization: 'Bearer do-not-expose' },
      body: Buffer.from('classified body').toString('base64'),
      agent_proof: {
        agent: 'private-agent', public_key: 'x'.repeat(32), signature: 'signature',
        timestamp: createdAt, nonce: 'abcdefgh', body_hash: '33'.repeat(32), host: 'secret.lattice',
      },
      response_key_id: responseKey.keyId,
      response_public_key: responseKey.publicKey,
    };
    const requestEnvelope = await sealHpkeJson(gatewayEncryption.publicKey, {
      direction: 'request', keyId: gatewayEncryption.keyId, requestId, routeHash, createdAt, expiresAt,
    }, secretRequest);

    const relayView = JSON.stringify({ id: requestId, payload: { e2e: requestEnvelope } });
    for (const forbidden of ['private-agent', 'secret.lattice', '/private/path', 'do-not-expose', 'classified body']) {
      expect(relayView).not.toContain(forbidden);
    }

    const openedRequest = parseE2eRequest(await backend.hpkeOpen(gatewayEncryption.keyId, requestEnvelope));
    expect(openedRequest.source).toBe('private-agent');

    const unsigned: E2eResponseUnsigned = {
      version: 1,
      request_id: requestId,
      route_hash: routeHash,
      status: 200,
      headers: { 'content-type': 'application/json' },
      body: Buffer.from('{"ok":true}').toString('base64'),
      gateway_identity_key_id: identity.keyId,
      gateway_identity_public_key: identity.publicKey,
    };
    const signature = await backend.signEd25519(identity.keyId, gatewayResponseSignaturePayload(unsigned));
    const responseEnvelope = await sealHpkeJson(responseKey.publicKey, {
      direction: 'response', keyId: responseKey.keyId, requestId, routeHash, createdAt, expiresAt,
    }, { ...unsigned, signature: signature.toString('base64url') });
    const response = parseE2eResponse(await openHpkeJson(responseKey.privateKey, responseEnvelope));
    expect(verifyGatewayResponse(response, identity.publicKey)).toBe(true);

    const attacker = crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: { format: 'der', type: 'spki' },
      privateKeyEncoding: { format: 'der', type: 'pkcs8' },
    });
    expect(verifyGatewayResponse(response, Buffer.from(attacker.publicKey).toString('base64'))).toBe(false);
    fs.rmSync(dir, { recursive: true, force: true });
  });
});
