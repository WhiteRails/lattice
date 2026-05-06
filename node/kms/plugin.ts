import { spawn } from 'child_process';

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
      const timeout = setTimeout(() => {
        try { child.kill('SIGTERM'); } catch {}
        reject(new Error('KMS plugin timed out after 10s'));
      }, 10000);
      child.stdout.on('data', (d: Buffer) => { out += d.toString(); });
      child.on('close', (code) => {
        clearTimeout(timeout);
        if (code !== 0) return reject(new Error(`KMS plugin exited with code ${code}`));
        try {
          const res = JSON.parse(out);
          if (res.error) return reject(new Error(res.error));
          resolve(res.result);
        } catch { reject(new Error('Invalid KMS plugin response')); }
      });
      child.stdin.write(JSON.stringify(req) + '\n');
      child.stdin.end();
    });
  }
}
