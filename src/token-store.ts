/**
 * Token store — persists OAuth2 tokens encrypted at rest.
 *
 * Each provider's tokens are stored as an AES-256-GCM encrypted file
 * in the plugin's data directory under Homebridge's persist path.
 * A random encryption key is auto-generated on first use.
 */

import { mkdir, readFile, writeFile, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import type { TokenSet } from './types';
import { TokenEncryption } from './token-encryption';

const PLUGIN_DATA_DIR = 'homebridge-oauth2-oidc';
const TOKEN_FILE_PREFIX = 'token_';

export class TokenStore {
  private dataDir: string;
  private encryption: TokenEncryption;

  constructor(baseStoragePath: string) {
    this.dataDir = join(baseStoragePath, PLUGIN_DATA_DIR);
    this.encryption = new TokenEncryption(this.dataDir);
  }

  private async ensureDataDir(): Promise<void> {
    await mkdir(this.dataDir, { recursive: true });
  }

  private filePath(providerId: string): string {
    return join(this.dataDir, `${TOKEN_FILE_PREFIX}${providerId}.json`);
  }

  async get(providerId: string): Promise<TokenSet | null> {
    try {
      const raw = await readFile(this.filePath(providerId), 'utf-8');
      return this.encryption.decrypt<TokenSet>(raw);
    } catch {
      return null;
    }
  }

  async set(providerId: string, tokenSet: TokenSet): Promise<void> {
    await this.ensureDataDir();
    const data = this.encryption.encrypt(tokenSet);
    await writeFile(this.filePath(providerId), data, 'utf-8');
  }

  async delete(providerId: string): Promise<void> {
    try {
      await unlink(this.filePath(providerId));
    } catch {
      // File doesn't exist — nothing to delete
    }
  }
}
