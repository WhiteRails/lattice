import { afterEach, describe, expect, it, vi } from 'vitest';
import * as crypto from 'crypto';
import * as fs from 'fs';
import * as http from 'http';
import * as os from 'os';
import * as path from 'path';

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

async function get(port: number, route: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    http.get({ host: '127.0.0.1', port, path: route }, response => {
      const chunks: Buffer[] = [];
      response.on('data', chunk => chunks.push(Buffer.from(chunk)));
      response.on('end', () => resolve({ status: response.statusCode ?? 0, body: Buffer.concat(chunks).toString('utf8') }));
    }).once('error', reject);
  });
}

describe('cell metrics', () => {
  it('exports bounded, principal-free Entry health and capacity metrics', async () => {
    const home = fs.mkdtempSync(path.join(os.tmpdir(), 'lat-metrics-'));
    homes.push(home);
    process.env.LATTICE_HOME = home;
    vi.resetModules();
    const { initDirs, saveCA } = await import('../node/state');
    initDirs();
    saveCA({
      caId: 'ca.metrics', publicKey: 'public', privateKey: 'private',
      overlaySecret: crypto.randomBytes(32).toString('base64'), createdAt: new Date().toISOString(),
    });
    const { EntryNode } = await import('../node/entry');
    const port = await freePort();
    const entry = new EntryNode({ port, nodeConfig: null, relayUrls: ['ws://127.0.0.1:1'] });
    try {
      expect((await get(port, '/healthz')).status).toBe(200);
      const metrics = await get(port, '/metrics');
      expect(metrics.status).toBe(200);
      expect(metrics.body).toContain('lattice_overlay_inflight{role="entry"}');
      expect(metrics.body).toContain('lattice_overlay_inflight_limit{role="entry"} 4096');
      expect(metrics.body).toContain('lattice_overlay_failures_total{role="entry"} 0');
      expect(metrics.body).toContain('lattice_issuer_certificate_cache_entries{role="entry"} 0');
      expect(metrics.body).not.toContain('bot1');
    } finally {
      entry.close();
    }
  });
});
