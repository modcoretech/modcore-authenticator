/* background.js */
'use strict';

importScripts('crypto.js');

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'GET_AUTOFILL_CODES') {
    handleAutofillRequest(sender).then(r => sendResponse(r)).catch(() => sendResponse({ codes: [] }));
    return true;
  }
});

async function handleAutofillRequest(sender) {
  try {
    const session = await chrome.storage.session.get(StorageKeys.SESSION_CEK);
    if (!session[StorageKeys.SESSION_CEK]) return { codes: [] };

    const rawCEK = Uint8Array.from(atob(session[StorageKeys.SESSION_CEK]), c => c.charCodeAt(0));
    const cek = await crypto.subtle.importKey('raw', rawCEK, 'AES-GCM', false, ['encrypt', 'decrypt']);

    const local = await chrome.storage.local.get([StorageKeys.VAULT, StorageKeys.SETTINGS]);
    if (!local[StorageKeys.VAULT]) return { codes: [] };

    const settings = local[StorageKeys.SETTINGS] || {};
    if (settings.autofill !== true) return { codes: [] };

    const plain = await CryptoUtils.decryptWithKey(local[StorageKeys.VAULT], cek);
    const accounts = JSON.parse(plain);

    const url = sender?.tab?.url || '';
    const domain = extractDomain(url);

    const codes = [];
    for (const acc of accounts) {
      const code = await TOTP.generate(acc.secret, acc.algo, acc.digits, acc.period);
      const recommended = matchDomain(domain, acc.issuer);
      codes.push({ id: acc.id, issuer: acc.issuer, account: acc.account, code, recommended });
    }
    codes.sort((a, b) => (b.recommended ? 1 : 0) - (a.recommended ? 1 : 0));
    return { codes };
  } catch {
    return { codes: [] };
  }
}

function extractDomain(url) {
  try {
    return new URL(url).hostname.replace(/^www\./, '').toLowerCase();
  } catch {
    return '';
  }
}

function matchDomain(domain, issuer) {
  if (!domain || !issuer) return false;
  const iss = issuer.toLowerCase().replace(/[^a-z0-9]/g, '');
  const dom = domain.replace(/\.(com|net|org|io|co\.[a-z]{2})$/, '');
  return dom.includes(iss) || iss.includes(dom);
}