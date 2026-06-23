/**
 * Token encryption at rest using AES-256-GCM.
 *
 * A random 256-bit key is generated on first use and persisted to disk
 * alongside the tokens. No user configuration required — encryption is
 * always enabled and fully automatic.
 */

import {
  randomBytes,
  createCipheriv,
  createDecipheriv,
} from 'node:crypto';
import {
  readFileSync,
  writeFileSync,
  existsSync,
  mkdirSync,
} from 'node:fs';
import { join } from 'node:path';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const KEY_FILE = '.encryption-key';

/**
 * Load or generate the encryption key, persisted in the given directory.
 */
export function loadOrCreateKey(dataDir: string): Buffer {
  const keyPath = join(dataDir, KEY_FILE);

  if (existsSync(keyPath)) {
    return Buffer.from(readFileSync(keyPath));
  }

  // Ensure the directory exists
  if (!existsSync(dataDir)) {
    mkdirSync(dataDir, { recursive: true });
  }

  const key = randomBytes(32);
  writeFileSync(keyPath, key);
  return key;
}

export class TokenEncryption {
  private readonly key: Buffer;

  constructor(dataDir: string) {
    this.key = loadOrCreateKey(dataDir);
  }

  encrypt(plaintext: unknown): string {
    const iv = randomBytes(IV_LENGTH);
    const cipher = createCipheriv(ALGORITHM, this.key, iv);

    const json = JSON.stringify(plaintext);
    const encrypted = Buffer.concat([
      cipher.update(json, 'utf-8'),
      cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();

    const combined = Buffer.concat([iv, authTag, encrypted]);
    return combined.toString('base64');
  }

  decrypt<T = unknown>(encryptedData: string): T {
    const combined = Buffer.from(encryptedData, 'base64');

    const iv = combined.subarray(0, IV_LENGTH);
    const authTag = combined.subarray(IV_LENGTH, IV_LENGTH + AUTH_TAG_LENGTH);
    const ciphertext = combined.subarray(IV_LENGTH + AUTH_TAG_LENGTH);

    const decipher = createDecipheriv(ALGORITHM, this.key, iv);
    decipher.setAuthTag(authTag);

    const decrypted = Buffer.concat([
      decipher.update(ciphertext),
      decipher.final(),
    ]);

    return JSON.parse(decrypted.toString('utf-8')) as T;
  }
}
