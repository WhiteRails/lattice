import { spawn } from 'child_process';

const MAX_KMS_PLUGIN_OUTPUT_BYTES = 64 * 1024;

export class PluginBackend {
  get type() { return 'plugin' as const; }

  constructor(private pluginCommand: string) {
    if (!pluginCommand) throw new Error('LATTICE_KMS_PLUGIN_COMMAND is required for plugin KMS backend');
  }

  async getKey(keyId: string): Promise<string> {
    return this.call({ method: 'getKey', keyId });
  }

  async sign(keyId: string, payload: string): Promise<string> {
    return this.call({ method: 'sign', keyId, payload });
  }

  private call(req: object): Promise<string> {
    return new Promise((resolve, reject) => {
      const [cmd, ...args] = this.pluginCommand.split(' ');
      if (/[;&|`$(){}]/.test(cmd)) {
        return reject(new Error('KMS plugin command contains forbidden shell metacharacters'));
      }
      const child = spawn(cmd, args, { stdio: ['pipe', 'pipe', 'inherit'], shell: false });
      let out = '';
      let outputBytes = 0;
      let settled = false;
      const finish = (error?: Error, result?: string) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        if (error) reject(error);
        else resolve(result!);
      };
      const timeout = setTimeout(() => {
        try { child.kill('SIGTERM'); } catch {}
        finish(new Error('KMS plugin timed out after 10s'));
      }, 10000);
      child.stdout.on('data', (d: Buffer) => {
        outputBytes += d.length;
        if (outputBytes > MAX_KMS_PLUGIN_OUTPUT_BYTES) {
          try { child.kill('SIGTERM'); } catch {}
          finish(new Error(`KMS plugin response exceeds ${MAX_KMS_PLUGIN_OUTPUT_BYTES} bytes`));
          return;
        }
        out += d.toString('utf8');
      });
      child.on('close', (code) => {
        if (code !== 0) return finish(new Error(`KMS plugin exited with code ${code}`));
        try {
          const res = JSON.parse(out);
          if (res.error) return finish(new Error(res.error));
          if (typeof res.result !== 'string') return finish(new Error('Invalid KMS plugin result'));
          finish(undefined, res.result);
        } catch { finish(new Error('Invalid KMS plugin response')); }
      });
      child.on('error', error => finish(error));
      child.stdin.write(JSON.stringify(req) + '\n');
      child.stdin.end();
    });
  }
}
