/* crypto.js */
'use strict';

const CryptoUtils = {
  async generateCEK() {
    return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  },

  async wrapKey(keyToWrap, wrappingKey) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const exported = await crypto.subtle.exportKey('raw', keyToWrap);
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, wrappingKey, exported);
    return {
      iv: btoa(String.fromCharCode(...iv)),
      ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertext)))
    };
  },

  async unwrapKey(wrapped, unwrappingKey) {
    const iv = Uint8Array.from(atob(wrapped.iv), c => c.charCodeAt(0));
    const ciphertext = Uint8Array.from(atob(wrapped.ciphertext), c => c.charCodeAt(0));
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, unwrappingKey, ciphertext);
    return crypto.subtle.importKey('raw', decrypted, 'AES-GCM', true, ['encrypt', 'decrypt']);
  },

  async encryptWithKey(plaintext, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plaintext));
    return {
      iv: btoa(String.fromCharCode(...iv)),
      ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertext)))
    };
  },

  async decryptWithKey(payload, key) {
    const dec = new TextDecoder();
    const iv = Uint8Array.from(atob(payload.iv), c => c.charCodeAt(0));
    const ciphertext = Uint8Array.from(atob(payload.ciphertext), c => c.charCodeAt(0));
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    return dec.decode(plain);
  },

  async deriveKeyFromPRF(prfResult) {
    const hash = await crypto.subtle.digest('SHA-256', prfResult);
    return crypto.subtle.importKey('raw', hash, 'AES-GCM', false, ['encrypt', 'decrypt']);
  },

  async deriveKeyFromPassword(password, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 600000, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  },

  generateRecoveryCode() {
    const bytes = crypto.getRandomValues(new Uint8Array(24));
    const b32 = base32Encode(bytes);
    return b32.match(/.{1,4}/g).join('-');
  }
};

function base32Encode(bytes) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, value = 0, out = '';
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += alphabet[(value << (5 - bits)) & 31];
  return out;
}

const TOTP = {
  async generate(secret, algo = 'SHA-1', digits = 6, period = 30, offset = 0) {
    try {
      const b32 = secret.toUpperCase().replace(/[^A-Z2-7]/g, '');
      if (!b32) return '------';
      const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
      let bits = 0, value = 0, idx = 0;
      const out = new Uint8Array(Math.floor(b32.length * 5 / 8));
      for (const ch of b32) {
        value = (value << 5) | alphabet.indexOf(ch);
        bits += 5;
        if (bits >= 8) {
          out[idx++] = (value >>> (bits - 8)) & 0xFF;
          bits -= 8;
        }
      }
      const counter = Math.floor(Math.floor(Date.now() / 1000) / period) + offset;
      const buf = new ArrayBuffer(8);
      new DataView(buf).setBigUint64(0, BigInt(counter), false);
      const key = await crypto.subtle.importKey('raw', out, { name: 'HMAC', hash: algo }, false, ['sign']);
      const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, buf));
      const off = sig[sig.length - 1] & 0xF;
      const bin = ((sig[off] & 0x7F) << 24) | ((sig[off + 1] & 0xFF) << 16) | ((sig[off + 2] & 0xFF) << 8) | (sig[off + 3] & 0xFF);
      return (bin % Math.pow(10, digits)).toString().padStart(digits, '0');
    } catch {
      return 'INVALID';
    }
  },

  getTimeRemaining(period) {
    return period - (Math.floor(Date.now() / 1000) % period);
  },

  getProgress(period) {
    const rem = this.getTimeRemaining(period);
    return ((period - rem) / period) * 100;
  }
};

const StorageKeys = {
  PASSKEYS: 'modcore_passkeys',
  RECOVERY_SALT: 'modcore_recovery_salt',
  WRAPPED_KEY_RECOVERY: 'modcore_wrapped_key_recovery',
  VAULT: 'modcore_vault',
  SETTINGS: 'modcore_settings',
  SESSION_CEK: 'modcore_session_cek'
};