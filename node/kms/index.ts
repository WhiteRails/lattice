export interface KMSBackend {
  type: 'local' | 'env' | 'plugin';
  getKey(keyId: string): Promise<string>;
  sign(keyId: string, payload: string): Promise<string>;
}

export function createKMSBackend(config?: { backend?: string; pluginCommand?: string; keyDir?: string }): KMSBackend {
  const backend = config?.backend ?? process.env.LATTICE_KMS_BACKEND ?? 'local';
  if (backend === 'env') {
    const { EnvBackend } = require('./env');
    return new EnvBackend();
  }
  if (backend === 'plugin') {
    const { PluginBackend } = require('./plugin');
    return new PluginBackend(config?.pluginCommand ?? process.env.LATTICE_KMS_PLUGIN_COMMAND ?? '');
  }
  const { LocalFileBackend } = require('./local');
  return new LocalFileBackend(config?.keyDir);
}
