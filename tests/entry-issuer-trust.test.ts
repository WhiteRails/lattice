import { afterEach, describe, expect, it, vi } from 'vitest';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';
import { LatticeCA } from '../core/ca';
import { generateKeyPair, hashRequestBody, requestSignaturePayload, signData } from '../core/identity';

const homes: string[] = [];

afterEach(() => {
  for (const home of homes.splice(0)) fs.rmSync(home, { recursive: true, force: true });
  delete process.env.LATTICE_HOME;
  vi.resetModules();
});

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const probe = http.createServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const address = probe.address();
      probe.close(() => typeof address === 'object' && address ? resolve(address.port) : reject(new Error('no port')));
    });
  });
}

describe('Entry portable issuer trust', () => {
  it('admits a valid portable certificate from a configured issuer without a local agent file', async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lat-entry-issuer-'));
    homes.push(home);
    process.env.LATTICE_HOME = home;
    vi.resetModules();
    const { initDirs, saveCA } = await import('../node/state');
    initDirs();
    const localCa = new LatticeCA('entry.local');
    saveCA({
      caId: localCa.id, publicKey: localCa.publicKey, privateKey: localCa.privateKey,
      overlaySecret: crypto.randomBytes(32).toString('base64'), createdAt: new Date().toISOString(),
    });

    const issuer = new LatticeCA('agents.example');
    const agent = generateKeyPair();
    const signed = issuer.issueAgentCert({
      agent_id: 'agent:agents.example:remote', owner_org: 'example', agent_type: 'autonomous', version: '1',
      public_key: agent.publicKey, allowed_capability_classes: [], forbidden_capability_classes: [], expires_in_days: 1,
    });
    const { EntryNode } = await import('../node/entry');
    const entry = new EntryNode({
      port: await freePort(),
      nodeConfig: { agentTrust: { issuers: [{ issuer_id: issuer.id, public_key: issuer.publicKey }] } } as any,
      relayUrls: ['ws://127.0.0.1:1'],
    });
    try {
      const timestamp = new Date().toISOString();
      const body = Buffer.alloc(0);
      const signature = signData(requestSignaturePayload({
        agent: 'remote', method: 'GET', host: 'echo.lattice', url: '/ping', timestamp, bodyHash: hashRequestBody(body),
      }), agent.privateKey);
      const request = {
        method: 'GET',
        url: '/ping',
        headers: {
          host: 'echo.lattice',
          'x-lattice-agent': 'remote',
          'x-lattice-signature': signature,
          'x-lattice-timestamp': timestamp,
          'x-lattice-nonce': 'portable-issuer-nonce-0001',
          'x-lattice-agent-certificate': Buffer.from(JSON.stringify(signed), 'utf8').toString('base64url'),
        },
      } as unknown as http.IncomingMessage;

      const result = await (entry as any).verifyAgentRequest(request, 'remote', body);
      expect(result.ok).toBe(true);
      expect(result.proof.public_key).toBe(agent.publicKey);
      expect(result.proof.certificate).toEqual(signed);
    } finally {
      entry.close();
    }
  });

  it('rejects a portable certificate from an issuer not configured for the cell', async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lat-entry-issuer-'));
    homes.push(home);
    process.env.LATTICE_HOME = home;
    vi.resetModules();
    const { initDirs, saveCA } = await import('../node/state');
    initDirs();
    const localCa = new LatticeCA('entry.local');
    saveCA({
      caId: localCa.id, publicKey: localCa.publicKey, privateKey: localCa.privateKey,
      overlaySecret: crypto.randomBytes(32).toString('base64'), createdAt: new Date().toISOString(),
    });
    const issuer = new LatticeCA('untrusted.example');
    const agent = generateKeyPair();
    const signed = issuer.issueAgentCert({
      agent_id: 'agent:untrusted:remote', owner_org: 'example', agent_type: 'autonomous', version: '1',
      public_key: agent.publicKey, allowed_capability_classes: [], forbidden_capability_classes: [], expires_in_days: 1,
    });
    const { EntryNode } = await import('../node/entry');
    const entry = new EntryNode({ port: await freePort(), nodeConfig: null, relayUrls: ['ws://127.0.0.1:1'] });
    try {
      const body = Buffer.alloc(0);
      const timestamp = new Date().toISOString();
      const request = {
        method: 'GET', url: '/ping',
        headers: {
          host: 'echo.lattice', 'x-lattice-agent': 'remote', 'x-lattice-timestamp': timestamp,
          'x-lattice-nonce': 'portable-issuer-nonce-0002',
          'x-lattice-signature': signData(requestSignaturePayload({
            agent: 'remote', method: 'GET', host: 'echo.lattice', url: '/ping', timestamp, bodyHash: hashRequestBody(body),
          }), agent.privateKey),
          'x-lattice-agent-certificate': Buffer.from(JSON.stringify(signed), 'utf8').toString('base64url'),
        },
      } as unknown as http.IncomingMessage;
      await expect((entry as any).verifyAgentRequest(request, 'remote', body)).resolves.toMatchObject({ ok: false, status: 401 });
    } finally {
      entry.close();
    }
  });
});
