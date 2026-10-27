/* js/crypto.js */
'use strict';

function bytesToBase64(bytes) {
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function base64ToBytes(b64) {
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
}

const CryptoUtils = {
  async generateCEK() {
    return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  },

  async wrapKey(keyToWrap, wrappingKey) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const exported = await crypto.subtle.exportKey('raw', keyToWrap);
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, wrappingKey, exported);
    return {
      iv: bytesToBase64(iv),
      ciphertext: bytesToBase64(new Uint8Array(ciphertext))
    };
  },

  async unwrapKey(wrapped, unwrappingKey) {
    const iv = base64ToBytes(wrapped.iv);
    const ciphertext = base64ToBytes(wrapped.ciphertext);
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, unwrappingKey, ciphertext);
    return crypto.subtle.importKey('raw', decrypted, 'AES-GCM', true, ['encrypt', 'decrypt']);
  },

  async encryptWithKey(plaintext, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const enc = new TextEncoder();
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plaintext));
    return {
      iv: bytesToBase64(iv),
      ciphertext: bytesToBase64(new Uint8Array(ciphertext))
    };
  },

  async decryptWithKey(payload, key) {
    const dec = new TextDecoder();
    const iv = base64ToBytes(payload.iv);
    const ciphertext = base64ToBytes(payload.ciphertext);
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

function base32Decode(str) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const b32 = (str || '').toUpperCase().replace(/[^A-Z2-7]/g, '');
  if (!b32) return null;
  let bits = 0, value = 0, idx = 0;
  const out = new Uint8Array(Math.floor(b32.length * 5 / 8));
  for (const ch of b32) {
    const n = alphabet.indexOf(ch);
    if (n < 0) return null;
    value = (value << 5) | n;
    bits += 5;
    if (bits >= 8) {
      out[idx++] = (value >>> (bits - 8)) & 0xFF;
      bits -= 8;
    }
  }
  return out;
}

const TOTP = {
  async generate(secret, algo = 'SHA-1', digits = 6, period = 30, offset = 0) {
    try {
      const keyBytes = base32Decode(secret);
      if (!keyBytes || keyBytes.length === 0) return '------';
      const counter = Math.floor(Math.floor(Date.now() / 1000) / period) + offset;
      const buf = new ArrayBuffer(8);
      new DataView(buf).setBigUint64(0, BigInt(counter), false);
      const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: algo }, false, ['sign']);
      const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, buf));
      const off = sig[sig.length - 1] & 0xF;
      const bin = (BigInt(sig[off] & 0x7F) << 24n)
                | (BigInt(sig[off + 1]) << 16n)
                | (BigInt(sig[off + 2]) << 8n)
                | BigInt(sig[off + 3]);
      const mod = 10n ** BigInt(digits);
      return (bin % mod).toString().padStart(digits, '0');
    } catch {
      return '------';
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

const Validators = {
  isValidBase32(str) {
    const s = (str || '').replace(/\s+/g, '').toUpperCase();
    return /^[A-Z2-7]+=*$/.test(s) && s.replace(/=+$/, '').length >= 8;
  },
  isValidDigits(n) {
    return Number.isInteger(n) && n >= 4 && n <= 10;
  },
  isValidPeriod(n) {
    return Number.isInteger(n) && n >= 5 && n <= 300;
  },
  sanitizeTags(tags) {
    if (!Array.isArray(tags)) return [];
    return tags
      .map(t => String(t).trim().replace(/,/g, '').toLowerCase())
      .filter(t => t && t.length <= 32)
      .slice(0, 20);
  }
};