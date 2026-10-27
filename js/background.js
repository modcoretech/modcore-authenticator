/* js/background.js */
'use strict';

importScripts('crypto.js');

// Open side panel on action click if supported
if (chrome.sidePanel && chrome.sidePanel.setPanelBehavior) {
  chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }).catch((e) => {
    console.warn('Side panel setup failed', e);
  });
}

const MIN_REQUEST_INTERVAL_MS = 400;
const lastRequestByTab = new Map();

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'GET_AUTOFILL_CODES') {
    handleAutofillRequest(sender)
      .then(r => sendResponse(r))
      .catch(() => sendResponse({ codes: [] }));
    return true;
  }
});

async function handleAutofillRequest(sender) {
  try {
    if (!sender || !sender.tab || typeof sender.tab.url !== 'string' || !sender.tab.url) {
      return { codes: [] };
    }

    const tabId = sender.tab.id;
    const now = Date.now();
    const last = lastRequestByTab.get(tabId) || 0;
    if (now - last < MIN_REQUEST_INTERVAL_MS) return { codes: [] };
    lastRequestByTab.set(tabId, now);

    const session = await chrome.storage.session.get(StorageKeys.SESSION_CEK);
    if (!session[StorageKeys.SESSION_CEK]) return { codes: [] };

    const rawCEK = base64ToBytes(session[StorageKeys.SESSION_CEK]);
    const cek = await crypto.subtle.importKey('raw', rawCEK, 'AES-GCM', false, ['encrypt', 'decrypt']);

    const local = await chrome.storage.local.get([StorageKeys.VAULT, StorageKeys.SETTINGS]);
    if (!local[StorageKeys.VAULT]) return { codes: [] };

    const settings = local[StorageKeys.SETTINGS] || {};
    if (settings.autofill !== true) return { codes: [] };

    const plain = await CryptoUtils.decryptWithKey(local[StorageKeys.VAULT], cek);
    const accounts = JSON.parse(plain);
    if (!Array.isArray(accounts)) return { codes: [] };

    const domain = extractDomain(sender.tab.url);
    const codes = [];
    for (const acc of accounts) {
      if (!acc || typeof acc.secret !== 'string') continue;
      let code;
      try {
        code = await TOTP.generate(acc.secret, acc.algo, acc.digits, acc.period);
      } catch {
        continue;
      }
      const recommended = matchDomain(domain, acc.issuer);
      codes.push({
        id: acc.id,
        issuer: acc.issuer,
        account: acc.account,
        code,
        recommended
      });
    }
    codes.sort((a, b) => (b.recommended ? 1 : 0) - (a.recommended ? 1 : 0));

    if (lastRequestByTab.size > 32) {
      for (const [id, t] of lastRequestByTab) {
        if (now - t > 60000) lastRequestByTab.delete(id);
      }
    }

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

function getRegistrableDomain(hostname) {
  const parts = hostname.split('.').filter(Boolean);
  if (parts.length <= 2) return hostname;
  const twoLevel = new Set([
    'co.uk', 'co.jp', 'co.in', 'co.nz', 'co.za', 'com.au', 'com.br',
    'com.mx', 'com.sg', 'com.hk', 'com.tw', 'com.cn', 'co.kr', 'ne.jp'
  ]);
  const lastTwo = parts.slice(-2).join('.');
  if (twoLevel.has(lastTwo)) return parts.slice(-3).join('.');
  return parts.slice(-2).join('.');
}

function matchDomain(domain, issuer) {
  if (!domain || !issuer) return false;
  const iss = String(issuer).toLowerCase().replace(/[^a-z0-9]/g, '');
  if (iss.length < 3) return false;
  const base = getRegistrableDomain(domain.toLowerCase());
  const baseLabel = base.split('.')[0].replace(/[^a-z0-9]/g, '');
  return iss.includes(baseLabel) || baseLabel.includes(iss);
}