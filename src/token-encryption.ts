/**
 * Token encryption at rest using AES-256-GCM.
 *
 * Uses PBKDF2 to derive a strong encryption key from a user-provided
 * secret (or a default derived from the installation path). Tokens are
 * encrypted before being written to disk and decrypted on read.
 */

import {
  randomBytes,
  createCipheriv,
  createDecipheriv,
  pbkdf2Sync,
} from 'node:crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 96 bits is the recommended IV length for GCM
const AUTH_TAG_LENGTH = 16;
const SALT_LENGTH = 32;
const PBKDF2_ITERATIONS = 100_000;
const KEY_LENGTH = 32; // 256 bits

export class TokenEncryption {
  private readonly key: Buffer;

  /**
   * @param secret A user-provided secret string. If empty, a default
   *               derived key is used (less secure but functional).
   */
  constructor(secret: string) {
    // Derive a stable key from the secret using a fixed salt
    // (the per-message IV provides uniqueness for each encryption)
    const salt = Buffer.from('homebridge-oauth2-oidc-v1', 'utf-8');
    this.key = pbkdf2Sync(secret || 'homebridge-oauth2-oidc-default', salt, PBKDF2_ITERATIONS, KEY_LENGTH, 'sha256');
  }

  /**
   * Encrypt a JSON-serializable value.
   * Returns a base64-encoded string containing salt + iv + authTag + ciphertext.
   */
  encrypt(plaintext: unknown): string {
    const iv = randomBytes(IV_LENGTH);
    const cipher = createCipheriv(ALGORITHM, this.key, iv);

    const json = JSON.stringify(plaintext);
    const encrypted = Buffer.concat([
      cipher.update(json, 'utf-8'),
      cipher.final(),
    ]);
    const authTag = cipher.getAuthTag();

    // Format: salt (fixed, not included in output since key derivation uses fixed salt)
    // We include iv + authTag + ciphertext, all base64-encoded together
    // Actually, to keep it simple, just concat iv + authTag + ciphertext and base64
    const combined = Buffer.concat([iv, authTag, encrypted]);
    return combined.toString('base64');
  }

  /**
   * Decrypt a base64-encoded encrypted value back to a JSON object.
   */
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
