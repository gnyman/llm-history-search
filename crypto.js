/**
 * ChatCrypto - Client-side decryption for encrypted chat search site
 * Compatible with Pagefind encryption format (PBKDF2 + AES-256-GCM)
 */
export class ChatCrypto {
  constructor(encryptionKey = null, derivedKeyHex = null) {
    this.encryptionKey = encryptionKey;
    this.derivedKeyBytes = derivedKeyHex
      ? ChatCrypto.hexToBytes(derivedKeyHex)
      : null;
    if (this.derivedKeyBytes && this.derivedKeyBytes.length !== 32) {
      throw new Error('Stored derived key is invalid');
    }
    this.decoder = new TextDecoder();
  }

  static hexToBytes(value) {
    if (!/^[0-9a-f]{64}$/i.test(value || '')) {
      return new Uint8Array();
    }
    const bytes = new Uint8Array(32);
    for (let i = 0; i < value.length; i += 2) {
      bytes[i / 2] = Number.parseInt(value.slice(i, i + 2), 16);
    }
    return bytes;
  }

  static bytesToHex(bytes) {
    return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Decrypt encrypted data in format:
   * [12 bytes: "pagefind_e2c" magic]
   * [1 byte: compression type (0x00=none, 0x01=gzip, 0x02=brotli)]
   * [1 byte: salt length]
   * [4 bytes: iterations, big-endian]
   * [N bytes: salt]
   * [12 bytes: nonce]
   * [remaining: AES-256-GCM ciphertext of possibly-compressed data]
   */
  async decrypt(encryptedData) {
    // Check magic header
    const magic = this.decoder.decode(encryptedData.slice(0, 12));
    if (magic !== 'pagefind_e2c') {
      throw new Error('Invalid encrypted file format (wrong magic header)');
    }

    // Parse header
    if (encryptedData.length < 12 + 1 + 1 + 4 + 12) {
      throw new Error('Encrypted file header is too short');
    }

    // Parse compression byte (always present)
    const compressionType = encryptedData[12];
    if (compressionType > 0x02) {
      throw new Error(`Unsupported compression type: ${compressionType}`);
    }

    const saltLen = encryptedData[13];
    const iterationsView = new DataView(
      encryptedData.buffer,
      encryptedData.byteOffset + 14,
      4
    );
    const iterations = iterationsView.getUint32(0, false); // big-endian

    // Extract components
    const saltStart = 18;  // 12 (magic) + 1 (compression) + 1 (salt_len) + 4 (iterations)
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

    let decrypted;
    try {
      decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: nonce },
        key,
        ciphertext
      );
    } catch (e) {
      throw new Error('Decryption failed (wrong key or corrupted data)');
    }

    let result = new Uint8Array(decrypted);

    // Decompress if needed
    if (compressionType === 0x01) {
      result = await this.decompressGzip(result);
    } else if (compressionType === 0x02) {
      result = await this.decompressBrotli(result);
    }

    return result;
  }

  /**
   * Derive encryption key from password using PBKDF2-HMAC-SHA256
   */
  async deriveKey(salt, iterations) {
    if (this.derivedKeyBytes) {
      return this.derivedKeyBytes.slice();
    }
    if (!this.encryptionKey) {
      throw new Error('No encryption password or derived key is available');
    }

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

  /**
   * Decompress data using DecompressionStream
   */
  async decompressStream(data, format) {
    const ds = new DecompressionStream(format);
    const writer = ds.writable.getWriter();
    writer.write(data);
    writer.close();

    const reader = ds.readable.getReader();
    const chunks = [];

    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
    }

    // Concatenate all chunks
    const totalLength = chunks.reduce((acc, chunk) => acc + chunk.length, 0);
    const result = new Uint8Array(totalLength);
    let offset = 0;
    for (const chunk of chunks) {
      result.set(chunk, offset);
      offset += chunk.length;
    }

    return result;
  }

  /**
   * Decompress gzip-compressed data
   */
  async decompressGzip(data) {
    if (typeof DecompressionStream === 'undefined') {
      throw new Error(
        'Browser does not support gzip decompression. ' +
        'Requires Chrome 80+, Firefox 68+, Safari 16.4+, or Edge 80+.'
      );
    }
    return await this.decompressStream(data, 'gzip');
  }

  /**
   * Decompress brotli-compressed data
   */
  async decompressBrotli(data) {
    if (typeof DecompressionStream === 'undefined') {
      throw new Error(
        'Browser does not support brotli decompression. ' +
        'Requires Chrome 80+, Firefox 68+, Safari 16.4+, or Edge 80+.'
      );
    }
    return await this.decompressStream(data, 'deflate-raw');
  }
}
