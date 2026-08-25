import { afterEach, describe, expect, it } from 'vitest';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { PluginBackend } from '../node/kms/plugin';

const dirs: string[] = [];

afterEach(() => {
  for (const dir of dirs.splice(0)) fs.rmSync(dir, { recursive: true, force: true });
});

function pluginScript(source: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'lat-kms-plugin-'));
  dirs.push(dir);
  const script = path.join(dir, 'plugin.js');
  fs.writeFileSync(script, source, { mode: 0o700 });
  return script;
}

describe('KMS plugin backend', () => {
  it('accepts a bounded JSON result from a plugin', async () => {
    const plugin = new PluginBackend(`${process.execPath} ${pluginScript("process.stdin.resume(); console.log(JSON.stringify({ result: 'signature' }));")}`);
    await expect(plugin.sign('key-1', 'payload')).resolves.toBe('signature');
  });

  it('terminates a plugin that attempts to return an unbounded response', async () => {
    const script = pluginScript("process.stdin.resume(); process.stdout.write('x'.repeat(65537));");
    const plugin = new PluginBackend(`${process.execPath} ${script}`);
    await expect(plugin.getKey('key-1')).rejects.toThrow(/exceeds/i);
  });
});
