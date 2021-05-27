declare module '@capacitor/core' {
  interface PluginRegistry {
    SecureStoragePlugin: SecureStoragePluginPlugin;
  }
}

export interface SecureStoragePluginPlugin {
  get(options: { key: string }): Promise<{ value: string }>;
  set(options: { key: string; value: string; mode: string }): Promise<{ value: boolean }>;
  remove(options: { key: string }): Promise<{ value: boolean }>;
  clear(): Promise<{ value: boolean }>;
  keys(): Promise<{ value: string[] }>;
  getPlatform(): Promise<{ value: string }>;
}
