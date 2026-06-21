/**
 * Token store — persists OAuth2 tokens using the filesystem with
 * optional AES-256-GCM encryption at rest.
 *
 * Each provider's tokens are stored as a JSON file in the plugin's
 * data directory under Homebridge's persist path. When encryption
 * is enabled, the file contents are encrypted before writing.
 */

import { mkdir, readFile, writeFile, unlink } from 'node:fs/promises';
import { join } from 'node:path';
import type { TokenSet } from './types';
import { TokenEncryption } from './token-encryption';

const PLUGIN_DATA_DIR = 'homebridge-oauth2-oidc';
const TOKEN_FILE_PREFIX = 'token_';

export class TokenStore {
  private dataDir: string;
  private encryption: TokenEncryption | null = null;

  constructor(baseStoragePath: string, encryptionSecret?: string) {
    this.dataDir = join(baseStoragePath, PLUGIN_DATA_DIR);
    if (encryptionSecret) {
      this.encryption = new TokenEncryption(encryptionSecret);
    }
  }

  private async ensureDataDir(): Promise<void> {
    await mkdir(this.dataDir, { recursive: true });
  }

  private filePath(providerId: string): string {
    return join(this.dataDir, `${TOKEN_FILE_PREFIX}${providerId}.json`);
  }

  /** Retrieve a stored token set for a provider */
  async get(providerId: string): Promise<TokenSet | null> {
    try {
      const raw = await readFile(this.filePath(providerId), 'utf-8');

      if (this.encryption) {
        return this.encryption.decrypt<TokenSet>(raw);
      }

      return JSON.parse(raw) as TokenSet;
    } catch {
      return null;
    }
  }

  /** Persist a token set for a provider */
  async set(providerId: string, tokenSet: TokenSet): Promise<void> {
    await this.ensureDataDir();

    const data = this.encryption
      ? this.encryption.encrypt(tokenSet)
      : JSON.stringify(tokenSet, null, 2);

    await writeFile(this.filePath(providerId), data, 'utf-8');
  }

  /** Delete stored tokens for a provider */
  async delete(providerId: string): Promise<void> {
    try {
      await unlink(this.filePath(providerId));
    } catch {
      // File doesn't exist — nothing to delete
    }
  }

  /** Check if encryption is enabled */
  get isEncrypted(): boolean {
    return this.encryption !== null;
  }
}
