/**
 * ChatCrypto - Client-side decryption for encrypted chat search site
 * Compatible with Pagefind encryption format (PBKDF2 + AES-256-GCM)
 */
export class ChatCrypto {
  constructor(encryptionKey) {
    this.encryptionKey = encryptionKey;
    this.decoder = new TextDecoder();
  }

  /**
   * Decrypt encrypted data in Pagefind format:
   * [12 bytes: "pagefind_e2c" magic]
   * [1 byte: salt length]
   * [4 bytes: iterations, big-endian]
   * [N bytes: salt]
   * [12 bytes: nonce]
   * [remaining: AES-256-GCM ciphertext]
   */
  async decrypt(encryptedData) {
    // Check magic header
    const magic = this.decoder.decode(encryptedData.slice(0, 12));
    if (magic !== 'pagefind_e2c') {
      throw new Error('Invalid encrypted file format (wrong magic header)');
    }

    // Parse header
    if (encryptedData.length < 12 + 1 + 4 + 12) {
      throw new Error('Encrypted file header is too short');
    }

    const saltLen = encryptedData[12];
    const iterationsView = new DataView(
      encryptedData.buffer,
      encryptedData.byteOffset + 13,
      4
    );
    const iterations = iterationsView.getUint32(0, false); // big-endian

    // Extract components
    const saltStart = 17;  // 12 (magic) + 1 (salt_len) + 4 (iterations)
    const saltEnd = saltStart + saltLen;
    const nonceStart = saltEnd;
    const nonceEnd = nonceStart + 12;

    if (encryptedData.length < nonceEnd) {
      throw new Error('Encrypted file is truncated');
    }

    const salt = encryptedData.slice(saltStart, saltEnd);
    const nonce = encryptedData.slice(nonceStart, nonceEnd);
    const ciphertext = encryptedData.slice(nonceEnd);

    // Derive key using PBKDF2
    const keyBytes = await this.deriveKey(salt, iterations);

    // Decrypt with AES-GCM
    const crypto = window.crypto;
    if (!crypto || !crypto.subtle) {
      throw new Error('Web Crypto API not available (requires HTTPS or localhost)');
    }

    const key = await crypto.subtle.importKey(
      'raw',
      keyBytes,
      'AES-GCM',
      false,
      ['decrypt']
    );

    try {
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce },
        key,
        ciphertext
      );

      return new Uint8Array(decrypted);
    } catch (e) {
      throw new Error('Decryption failed (wrong key or corrupted data)');
    }
  }

  /**
   * Derive encryption key from password using PBKDF2-HMAC-SHA256
   */
  async deriveKey(salt, iterations) {
    const crypto = window.crypto;
    if (!crypto || !crypto.subtle) {
      throw new Error('Web Crypto API not available');
    }

    const encoder = new TextEncoder();
    const keyData = encoder.encode(this.encryptionKey);

    // Import password as key material
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      keyData,
      'PBKDF2',
      false,
      ['deriveBits']
    );

    // Derive 256-bit key
    const bits = await crypto.subtle.deriveBits(
      {
        name: 'PBKDF2',
        salt: salt,
        iterations: iterations,
        hash: 'SHA-256'
      },
      keyMaterial,
      256  // 256 bits = 32 bytes
    );

    return new Uint8Array(bits);
  }

  /**
   * Decrypt and return as UTF-8 string
   */
  async decryptText(encryptedData) {
    const decrypted = await this.decrypt(encryptedData);
    return new TextDecoder().decode(decrypted);
  }
}
