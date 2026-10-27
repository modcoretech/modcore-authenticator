/* js/popup.js */
'use strict';

const el = (id) => document.getElementById(id);
const make = (tag, props = {}) => Object.assign(document.createElement(tag), props);

const DEFAULT_SETTINGS = {
  showIcons: true,
  showNextCode: true,
  showProgress: true,
  privacyMode: false,
  autoClear: true,
  autofill: true,
};

const SETTING_MAP = [
  ['toggle-icons', 'showIcons'],
  ['toggle-next-code', 'showNextCode'],
  ['toggle-progress', 'showProgress'],
  ['toggle-hide-codes', 'privacyMode'],
  ['toggle-copy-clear', 'autoClear'],
  ['toggle-autofill', 'autofill'],
];

function getFaviconUrl(issuer) {
  if (!issuer) return null;
  const clean = issuer.trim().toLowerCase();
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(clean)) {
    return `https://www.google.com/s2/favicons?domain=${clean}&sz=64`;
  }
  const domain = clean.replace(/[^a-z0-9]/g, '') + '.com';
  return `https://www.google.com/s2/favicons?domain=${domain}&sz=64`;
}

function getProviderColor(issuer) {
  let hash = 0;
  for (const c of String(issuer || '')) hash = ((hash << 5) - hash) + c.charCodeAt(0);
  const hue = Math.abs(hash) % 360;
  return `hsl(${hue},60%,45%)`;
}

async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (err) {
    console.error('Clipboard write failed:', err);
    return false;
  }
}

const App = {
  accounts: [],
  settings: { ...DEFAULT_SETTINGS },
  cek: null,
  filter: '',
  sortMode: 'default',
  editingId: null,
  isEditMode: false,
  addTags: [],
  editTags: [],
  _tickTimer: null,
  _toastTimer: null,
  _clearTimer: null,
  _dragSrcEl: null,

  async init() {
    try {
      await App.loadSettings();

      const session = await chrome.storage.session.get(StorageKeys.SESSION_CEK);
      if (session[StorageKeys.SESSION_CEK]) {
        try {
          await App.restoreCEK(session[StorageKeys.SESSION_CEK]);
          await App.decryptVault();
          el('lock-screen').classList.add('hidden');
          App.applySettings();
          await App.render();
          App.startTick();
        } catch (e) {
          console.error('Session restore failed', e);
          await chrome.storage.session.remove(StorageKeys.SESSION_CEK);
          App.showLock();
        }
      } else {
        const local = await chrome.storage.local.get(StorageKeys.VAULT);
        if (!local[StorageKeys.VAULT]) {
          App.showSetup();
        } else {
          App.showLock();
        }
      }
      App.bindEvents();
      App.bindKeyboardShortcuts();
    } catch (e) {
      console.error('Init failed', e);
      App.toast('Initialization failed');
    }
  },

  startTick() {
    if (App._tickTimer) clearInterval(App._tickTimer);
    App._tickTimer = setInterval(App.tick, 1000);
  },

  async restoreCEK(b64) {
    const raw = base64ToBytes(b64);
    App.cek = await crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
  },

  async decryptVault() {
    if (!App.cek) throw new Error('No CEK');
    const local = await chrome.storage.local.get(StorageKeys.VAULT);
    if (!local[StorageKeys.VAULT]) {
      App.accounts = [];
      return;
    }
    const plain = await CryptoUtils.decryptWithKey(local[StorageKeys.VAULT], App.cek);
    const parsed = JSON.parse(plain);
    App.accounts = Array.isArray(parsed) ? parsed : [];
  },

  async save() {
    if (!App.cek) return;
    try {
      const vault = await CryptoUtils.encryptWithKey(JSON.stringify(App.accounts), App.cek);
      await chrome.storage.local.set({ [StorageKeys.VAULT]: vault });
    } catch (e) {
      console.error('Save failed', e);
      App.toast('Failed to save data');
    }
  },

  async loadSettings() {
    const res = await chrome.storage.local.get(StorageKeys.SETTINGS);
    App.settings = Object.assign({}, DEFAULT_SETTINGS, res[StorageKeys.SETTINGS] || {});
  },

  applySettings() {
    for (const [id, key] of SETTING_MAP) {
      const node = el(id);
      if (node) node.checked = !!App.settings[key];
    }
  },

  showLock() {
    el('lock-screen').classList.remove('hidden');
    el('lock-unlock').classList.remove('hidden');
    el('lock-setup').classList.add('hidden');
    el('lock-recovery-setup').classList.add('hidden');
  },

  showSetup() {
    el('lock-screen').classList.remove('hidden');
    el('lock-unlock').classList.add('hidden');
    el('lock-setup').classList.remove('hidden');
    el('lock-recovery-setup').classList.add('hidden');
  },

  async setupPasskey() {
    try {
      App.toast('Creating passkey...');
      const prfSalt = crypto.getRandomValues(new Uint8Array(32));
      const challenge = crypto.getRandomValues(new Uint8Array(32));

      const cred = await navigator.credentials.create({
        publicKey: {
          challenge,
          rp: { name: 'modcore Authenticator', id: location.hostname },
          user: { id: crypto.getRandomValues(new Uint8Array(16)), name: 'modcore-user', displayName: 'User' },
          pubKeyCredParams: [
            { alg: -7, type: 'public-key' },
            { alg: -257, type: 'public-key' }
          ],
          authenticatorSelection: {
            authenticatorAttachment: 'platform',
            userVerification: 'required',
            residentKey: 'preferred',
            requireResidentKey: false
          },
          attestation: 'none',
          extensions: { prf: { eval: { first: prfSalt } } }
        }
      });

      let prfResult = cred.getClientExtensionResults().prf?.results?.first;

      if (!prfResult) {
        const assertion = await navigator.credentials.get({
          publicKey: {
            challenge: crypto.getRandomValues(new Uint8Array(32)),
            allowCredentials: [{ id: new Uint8Array(cred.rawId), type: 'public-key' }],
            userVerification: 'required',
            extensions: { prf: { eval: { first: prfSalt } } }
          }
        });
        prfResult = assertion.getClientExtensionResults().prf?.results?.first;
      }

      if (!prfResult) throw new Error('PRF extension not supported by this authenticator.');

      const prfKey = await CryptoUtils.deriveKeyFromPRF(prfResult);
      App.cek = await CryptoUtils.generateCEK();
      const rawCEK = await crypto.subtle.exportKey('raw', App.cek);
      await chrome.storage.session.set({ [StorageKeys.SESSION_CEK]: bytesToBase64(new Uint8Array(rawCEK)) });

      const recoveryCode = CryptoUtils.generateRecoveryCode();
      const recoveryCodeClean = recoveryCode.replace(/-/g, '');
      const recoverySalt = crypto.getRandomValues(new Uint8Array(16));
      const recoveryKey = await CryptoUtils.deriveKeyFromPassword(recoveryCodeClean, recoverySalt);

      const wrappedKey = await CryptoUtils.wrapKey(App.cek, prfKey);
      const wrappedKeyRecovery = await CryptoUtils.wrapKey(App.cek, recoveryKey);
      const vault = await CryptoUtils.encryptWithKey('[]', App.cek);

      const passkeyEntry = {
        id: bytesToBase64(new Uint8Array(cred.rawId)),
        prfSalt: bytesToBase64(prfSalt),
        wrappedKey,
        created: Date.now()
      };

      await chrome.storage.local.set({
        [StorageKeys.PASSKEYS]: [passkeyEntry],
        [StorageKeys.WRAPPED_KEY_RECOVERY]: wrappedKeyRecovery,
        [StorageKeys.RECOVERY_SALT]: bytesToBase64(recoverySalt),
        [StorageKeys.VAULT]: vault,
        [StorageKeys.SETTINGS]: DEFAULT_SETTINGS
      });

      App.accounts = [];
      App.settings = { ...DEFAULT_SETTINGS };
      App.applySettings();

      el('recovery-code-display').textContent = recoveryCode;
      el('lock-setup').classList.add('hidden');
      el('lock-recovery-setup').classList.remove('hidden');

      const chk = el('chk-saved-recovery');
      const btn = el('btn-continue-recovery');
      chk.checked = false;
      btn.disabled = true;
      chk.onchange = () => { btn.disabled = !chk.checked; };
      btn.onclick = () => {
        el('lock-screen').classList.add('hidden');
        App.render();
        App.startTick();
        App.toast('Vault created');
      };
    } catch (e) {
      console.error('Setup failed', e);
      Dialog.alert('Setup Failed', e.message || 'Could not create passkey. Ensure your device supports passkeys with PRF.');
    }
  },

  async unlockWithPasskey() {
    try {
      App.toast('Waiting for passkey...');
      const local = await chrome.storage.local.get(StorageKeys.PASSKEYS);
      const passkeys = local[StorageKeys.PASSKEYS] || [];
      if (!passkeys.length) throw new Error('No passkeys registered.');

      const allowCredentials = passkeys.map(pk => ({
        id: base64ToBytes(pk.id),
        type: 'public-key'
      }));

      const assertion = await navigator.credentials.get({
        publicKey: {
          challenge: crypto.getRandomValues(new Uint8Array(32)),
          allowCredentials,
          userVerification: 'required',
          extensions: { prf: { eval: { first: base64ToBytes(passkeys[0].prfSalt) } } }
        }
      });

      const prf = assertion.getClientExtensionResults().prf?.results?.first;
      if (!prf) throw new Error('PRF result not available. Ensure your passkey supports the PRF extension.');

      const prfKey = await CryptoUtils.deriveKeyFromPRF(prf);
      const usedId = bytesToBase64(new Uint8Array(assertion.rawId));
      const passkey = passkeys.find(pk => pk.id === usedId) || passkeys[0];

      App.cek = await CryptoUtils.unwrapKey(passkey.wrappedKey, prfKey);
      const rawCEK = await crypto.subtle.exportKey('raw', App.cek);
      await chrome.storage.session.set({ [StorageKeys.SESSION_CEK]: bytesToBase64(new Uint8Array(rawCEK)) });

      await App.decryptVault();
      el('lock-screen').classList.add('hidden');
      App.applySettings();
      await App.render();
      App.startTick();
      App.toast('Unlocked');
    } catch (e) {
      console.error('Unlock failed', e);
      App.toast('Unlock failed: ' + (e.message || 'Unknown error'));
    }
  },

  async unlockWithRecovery() {
    Dialog.prompt('Recovery Code', 'Enter your recovery code (dashes optional):', 'text', async (code) => {
      if (!code) return;
      try {
        const clean = code.toUpperCase().replace(/[^A-Z2-7]/g, '');
        if (clean.length < 20) throw new Error('Too short');
        const local = await chrome.storage.local.get([StorageKeys.WRAPPED_KEY_RECOVERY, StorageKeys.RECOVERY_SALT]);
        if (!local[StorageKeys.RECOVERY_SALT] || !local[StorageKeys.WRAPPED_KEY_RECOVERY]) throw new Error('No recovery data');
        const recoverySalt = base64ToBytes(local[StorageKeys.RECOVERY_SALT]);
        const recoveryKey = await CryptoUtils.deriveKeyFromPassword(clean, recoverySalt);
        App.cek = await CryptoUtils.unwrapKey(local[StorageKeys.WRAPPED_KEY_RECOVERY], recoveryKey);
        const rawCEK = await crypto.subtle.exportKey('raw', App.cek);
        await chrome.storage.session.set({ [StorageKeys.SESSION_CEK]: bytesToBase64(new Uint8Array(rawCEK)) });

        await App.decryptVault();
        el('lock-screen').classList.add('hidden');
        App.applySettings();
        await App.render();
        App.startTick();
        App.toast('Unlocked with recovery code');
      } catch (e) {
        console.error('Recovery unlock failed', e);
        Dialog.alert('Invalid Code', 'The recovery code is incorrect.');
      }
    });
  },

  async lockNow() {
    clearInterval(App._tickTimer);
    App._tickTimer = null;
    App.accounts = [];
    App.cek = null;
    App.filter = '';
    el('inp-search').value = '';
    el('btn-clear-search').classList.remove('visible');
    await chrome.storage.session.remove(StorageKeys.SESSION_CEK);
    document.querySelectorAll('.sheet').forEach(s => s.classList.add('hidden'));
    if (el('app-dialog').open) el('app-dialog').close();
    App.showLock();
  },

  async renderManagePasskeys() {
    const container = el('passkeys-list');
    container.textContent = '';
    const local = await chrome.storage.local.get(StorageKeys.PASSKEYS);
    const passkeys = local[StorageKeys.PASSKEYS] || [];

    if (!passkeys.length) {
      const empty = make('div', { className: 'form-row' });
      const span = make('span'); span.textContent = 'No passkeys registered';
      empty.appendChild(span);
      container.appendChild(empty);
      return;
    }

    passkeys.forEach((pk, idx) => {
      if (idx > 0) container.appendChild(make('div', { className: 'separator' }));
      const row = make('div', { className: 'form-row' });
      const info = make('span');
      const date = pk.created ? new Date(pk.created).toLocaleDateString() : 'Unknown';
      info.textContent = `Passkey ${idx + 1} — ${date}`;
      const delBtn = make('button', { className: 'list-btn small red', type: 'button' });
      delBtn.textContent = 'Delete';
      delBtn.title = 'Remove this passkey';
      delBtn.addEventListener('click', async () => {
        if (passkeys.length <= 1) {
          return Dialog.alert('Cannot Remove', 'You must keep at least one passkey or use recovery to add a new one.');
        }
        Dialog.confirm('Delete Passkey', 'Remove this passkey? You can still unlock with other passkeys or recovery.', async () => {
          const updated = passkeys.filter((_, i) => i !== idx);
          await chrome.storage.local.set({ [StorageKeys.PASSKEYS]: updated });
          App.renderManagePasskeys();
        });
      });
      row.append(info, delBtn);
      container.appendChild(row);
    });
  },

  async addNewPasskey() {
    try {
      App.toast('Registering new passkey...');
      const prfSalt = crypto.getRandomValues(new Uint8Array(32));
      const challenge = crypto.getRandomValues(new Uint8Array(32));

      const cred = await navigator.credentials.create({
        publicKey: {
          challenge,
          rp: { name: 'modcore Authenticator', id: location.hostname },
          user: { id: crypto.getRandomValues(new Uint8Array(16)), name: 'modcore-user', displayName: 'User' },
          pubKeyCredParams: [
            { alg: -7, type: 'public-key' },
            { alg: -257, type: 'public-key' }
          ],
          authenticatorSelection: {
            authenticatorAttachment: 'platform',
            userVerification: 'required',
            residentKey: 'preferred',
            requireResidentKey: false
          },
          attestation: 'none',
          extensions: { prf: { eval: { first: prfSalt } } }
        }
      });

      let prfResult = cred.getClientExtensionResults().prf?.results?.first;

      if (!prfResult) {
        const assertion = await navigator.credentials.get({
          publicKey: {
            challenge: crypto.getRandomValues(new Uint8Array(32)),
            allowCredentials: [{ id: new Uint8Array(cred.rawId), type: 'public-key' }],
            userVerification: 'required',
            extensions: { prf: { eval: { first: prfSalt } } }
          }
        });
        prfResult = assertion.getClientExtensionResults().prf?.results?.first;
      }

      if (!prfResult) throw new Error('PRF not supported.');

      const prfKey = await CryptoUtils.deriveKeyFromPRF(prfResult);
      if (!App.cek) throw new Error('Not unlocked');
      const wrappedKey = await CryptoUtils.wrapKey(App.cek, prfKey);

      const local = await chrome.storage.local.get(StorageKeys.PASSKEYS);
      const passkeys = local[StorageKeys.PASSKEYS] || [];
      passkeys.push({
        id: bytesToBase64(new Uint8Array(cred.rawId)),
        prfSalt: bytesToBase64(prfSalt),
        wrappedKey,
        created: Date.now()
      });

      await chrome.storage.local.set({ [StorageKeys.PASSKEYS]: passkeys });
      App.renderManagePasskeys();
      App.toast('Passkey added');
    } catch (e) {
      console.error('Add passkey failed', e);
      Dialog.alert('Error', e.message || 'Could not add passkey.');
    }
  },

  async resetRecoveryCode() {
    Dialog.confirm('Reset Recovery Code', 'This will invalidate your old recovery code and generate a new one. Continue?', async () => {
      try {
        if (!App.cek) throw new Error('Not unlocked');
        const newCode = CryptoUtils.generateRecoveryCode();
        const newCodeClean = newCode.replace(/-/g, '');
        const newSalt = crypto.getRandomValues(new Uint8Array(16));
        const newKey = await CryptoUtils.deriveKeyFromPassword(newCodeClean, newSalt);
        const newWrapped = await CryptoUtils.wrapKey(App.cek, newKey);

        await chrome.storage.local.set({
          [StorageKeys.WRAPPED_KEY_RECOVERY]: newWrapped,
          [StorageKeys.RECOVERY_SALT]: bytesToBase64(newSalt)
        });

        const body = make('div');
        const p = make('p'); p.textContent = 'Your new recovery code:';
        p.style.cssText = 'margin:0 16px 12px;font-size:13px;color:var(--color-text-secondary);';
        const codeDiv = make('div');
        codeDiv.textContent = newCode;
        codeDiv.style.cssText = 'padding:14px;font-family:var(--font-mono);font-size:16px;color:var(--color-primary);font-weight:600;word-break:break-all;background:var(--color-surface-high);border-radius:24px;margin:0 16px 16px;';
        body.append(p, codeDiv);

        Dialog.custom('New Recovery Code', body, [
          { label: 'Copy', action: async () => { await copyToClipboard(newCode); App.toast('Copied'); }, bold: false },
          { label: 'Done', action: null, bold: true }
        ]);
      } catch (e) {
        console.error('Reset recovery failed', e);
        App.toast('Failed to reset recovery code');
      }
    });
  },

  scanFromScreen() {
    chrome.tabs.captureVisibleTab(null, { format: 'png' }, (dataUrl) => {
      if (chrome.runtime.lastError) {
        return Dialog.alert('Capture Error', 'Could not capture the active tab. Make sure the tab is accessible.');
      }
      App.processQRImage(dataUrl);
    });
  },

  handleFileUpload(e) {
    const file = e.target.files[0];
    if (!file) return;
    if (!file.type.startsWith('image/')) return Dialog.alert('Invalid File', 'Please select an image file.');
    if (file.size > 5 * 1024 * 1024) return Dialog.alert('File Too Large', 'Image must be under 5 MB.');
    const reader = new FileReader();
    reader.onload = (evt) => App.processQRImage(evt.target.result);
    reader.onerror = () => Dialog.alert('Read Error', 'Could not read the file.');
    reader.readAsDataURL(file);
    e.target.value = '';
  },

  async processQRImage(dataUrl) {
    App.toast('Analyzing QR code…');
    try {
      const img = new Image();
      img.src = dataUrl;
      await new Promise((resolve, reject) => { img.onload = resolve; img.onerror = reject; });
      const canvas = document.createElement('canvas');
      canvas.width = img.width;
      canvas.height = img.height;
      const ctx = canvas.getContext('2d');
      ctx.drawImage(img, 0, 0);
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const code = jsQR(imageData.data, imageData.width, imageData.height);
      if (code && code.data) {
        App.parseOtpAuthUrl(code.data);
      } else {
        Dialog.alert('No QR Found', 'Could not detect a valid QR code in the image.');
      }
    } catch {
      Dialog.alert('Scan Error', 'Could not process the image.');
    }
  },

  parseOtpAuthUrl(url) {
    if (!url.startsWith('otpauth://')) {
      return Dialog.alert('Invalid QR', 'This is not a valid 2FA QR code (otpauth://).');
    }
    try {
      const u = new URL(url);
      const p = u.searchParams;
      const pathPart = decodeURIComponent(u.pathname.slice(1));
      const account = pathPart.includes(':') ? pathPart.split(':').slice(1).join(':') : pathPart;
      
      const secret = (p.get('secret') || '').replace(/\s+/g, '').toUpperCase();
      if (!Validators.isValidBase32(secret)) {
        return Dialog.alert('Invalid Secret', 'The QR code did not contain a valid Base32 secret.');
      }

      el('inp-issuer').value = p.get('issuer') || (pathPart.includes(':') ? pathPart.split(':')[0] : '') || 'Unknown';
      el('inp-account').value = account;
      el('inp-secret').value = secret;
      
      if (p.get('algorithm') && ['SHA-1', 'SHA-256', 'SHA-512'].includes(p.get('algorithm'))) {
        el('sel-algo').value = p.get('algorithm');
      }
      if (p.get('digits') && Validators.isValidDigits(parseInt(p.get('digits'), 10))) {
        el('inp-digits').value = p.get('digits');
      }
      if (p.get('period') && Validators.isValidPeriod(parseInt(p.get('period'), 10))) {
        el('inp-period').value = p.get('period');
      }

      App.validateAddForm();
      el('sheet-add').classList.remove('hidden');
      App.toast('QR code scanned');
    } catch {
      Dialog.alert('Parse Error', 'Could not parse the QR code.');
    }
  },

  addTag(tag, which = 'add') {
    const list = which === 'add' ? App.addTags : App.editTags;
    const trimmed = String(tag || '').trim().replace(/,/g, '').toLowerCase();
    if (trimmed && trimmed.length <= 32 && !list.includes(trimmed)) {
      list.push(trimmed);
      App.renderTags(which);
    }
  },

  removeTag(tag, which) {
    if (which === 'add') App.addTags = App.addTags.filter(t => t !== tag);
    else App.editTags = App.editTags.filter(t => t !== tag);
    App.renderTags(which);
  },

  renderTags(which = 'add') {
    const container = el(which === 'add' ? 'tag-container' : 'edit-tag-container');
    const inpId = which === 'add' ? 'inp-tags' : 'edit-inp-tags';
    const list = which === 'add' ? App.addTags : App.editTags;
    container.textContent = '';
    list.forEach(tag => {
      const chip = make('div', { className: 'tag-item', role: 'listitem' });
      const span = make('span'); span.textContent = '#' + tag;
      const btn = make('button', { className: 'tag-remove', type: 'button', 'aria-label': `Remove tag ${tag}` });
      btn.textContent = '×';
      btn.addEventListener('click', () => App.removeTag(tag, which));
      chip.append(span, btn);
      container.appendChild(chip);
    });
    el(inpId).value = '';
  },

  async addAccount() {
    const issuer = el('inp-issuer').value.trim();
    const secret = el('inp-secret').value.replace(/\s+/g, '').toUpperCase();
    const account = el('inp-account').value.trim();
    const digits = parseInt(el('inp-digits').value, 10);
    const period = parseInt(el('inp-period').value, 10);
    const algo = el('sel-algo').value;

    if (!issuer || !secret) return;
    if (!Validators.isValidBase32(secret)) {
      return Dialog.alert('Invalid Secret', 'Secret key must be valid Base32 (A-Z, 2-7).');
    }
    if (!Validators.isValidDigits(digits)) {
      return Dialog.alert('Invalid Digits', 'Digits must be between 4 and 10.');
    }
    if (!Validators.isValidPeriod(period)) {
      return Dialog.alert('Invalid Period', 'Period must be between 5 and 300 seconds.');
    }
    if (!['SHA-1', 'SHA-256', 'SHA-512'].includes(algo)) {
      return Dialog.alert('Invalid Algorithm', 'Unsupported algorithm.');
    }

    const acc = {
      id: Date.now().toString(36) + Math.random().toString(36).slice(2),
      issuer,
      account,
      secret,
      algo,
      digits,
      period,
      tags: [...App.addTags],
      pinned: false,
      created: Date.now(),
      lastUsed: null,
      usageCount: 0,
    };

    App.accounts.push(acc);
    await App.save();
    App.closeSheet('add');
    App.clearAddForm();
    await App.render();
    App.toast(`"${issuer}" added`);
  },

  deleteAccount() {
    Dialog.confirm('Delete Account', 'This will permanently remove this account and cannot be undone.', async () => {
      App.accounts = App.accounts.filter(a => a.id !== App.editingId);
      await App.save();
      App.closeSheet('edit');
      await App.render();
      App.toast('Account deleted');
    });
  },

  async togglePin() {
    const acc = App.accounts.find(a => a.id === App.editingId);
    if (!acc) return;
    acc.pinned = !acc.pinned;
    el('pin-label').textContent = acc.pinned ? 'Unpin Account' : 'Pin Account';
    await App.save();
    await App.render();
  },

  async shareCode() {
    const acc = App.accounts.find(a => a.id === App.editingId);
    if (!acc) return;
    const code = await TOTP.generate(acc.secret, acc.algo, acc.digits, acc.period);
    try {
      if (navigator.share) {
        await navigator.share({ title: `2FA for ${acc.issuer}`, text: `Code: ${code}` });
      } else {
        throw new Error('no share');
      }
    } catch {
      if (await copyToClipboard(code)) {
        App.toast('Code copied to clipboard');
      } else {
        App.toast('Failed to copy');
      }
    }
  },

  async copyOtpUrl() {
    const acc = App.accounts.find(a => a.id === App.editingId);
    if (!acc) return;
    const params = new URLSearchParams({
      secret: acc.secret,
      issuer: acc.issuer,
      algorithm: acc.algo,
      digits: String(acc.digits),
      period: String(acc.period),
    });
    const label = acc.account
      ? `${encodeURIComponent(acc.issuer)}:${encodeURIComponent(acc.account)}`
      : encodeURIComponent(acc.issuer);
    const url = `otpauth://totp/${label}?${params.toString()}`;
    if (await copyToClipboard(url)) {
      App.toast('otpauth URL copied');
    } else {
      App.toast('Copy failed');
    }
  },

  revealSecret() {
    const acc = App.accounts.find(a => a.id === App.editingId);
    if (!acc) return;
    const body = make('div');
    const p = make('p'); p.textContent = 'Secret Key (Base32):';
    p.style.cssText = 'margin:0 16px 12px;font-size:13px;color:var(--color-text-secondary);';
    const codeDiv = make('div');
    codeDiv.textContent = acc.secret;
    codeDiv.style.cssText = 'padding:14px;font-family:var(--font-mono);font-size:16px;color:var(--color-primary);font-weight:600;word-break:break-all;background:var(--color-surface-high);border-radius:24px;margin:0 16px 16px;';
    body.append(p, codeDiv);
    Dialog.custom('Secret Key', body, [
      { label: 'Copy', action: async () => { await copyToClipboard(acc.secret); App.toast('Copied'); }, bold: false },
      { label: 'Close', action: null, bold: true }
    ]);
  },

  openDuplicates() {
    const map = new Map();
    App.accounts.forEach(acc => {
      const key = (acc.secret || '').toUpperCase().replace(/\s+/g, '');
      if (!key) return;
      if (!map.has(key)) map.set(key, []);
      map.get(key).push(acc);
    });
    const dups = Array.from(map.values()).filter(arr => arr.length > 1);
    const content = el('duplicates-content');
    content.textContent = '';

    if (dups.length === 0) {
      const wrap = make('div', { className: 'empty-state' });
      const h3 = make('h3'); h3.textContent = 'No Duplicates';
      const p = make('p'); p.textContent = 'All your accounts have unique secrets.';
      wrap.append(h3, p);
      content.appendChild(wrap);
    } else {
      dups.forEach(group => {
        const groupWrap = make('div', { className: 'inset-group', style: 'margin-bottom:12px;' });
        const header = make('div', { className: 'form-row' });
        const name = make('span'); name.textContent = group[0].issuer;
        const count = make('span', { className: 'value' }); count.textContent = `${group.length} accounts`;
        header.append(name, count);
        groupWrap.appendChild(header);

        group.forEach(acc => {
          groupWrap.appendChild(make('div', { className: 'separator' }));
          const row = make('div', { className: 'form-row' });
          const info = make('span'); info.textContent = acc.account || 'No account';
          const delBtn = make('button', { className: 'list-btn small red', type: 'button' });
          delBtn.textContent = 'Delete';
          delBtn.addEventListener('click', async () => {
            App.accounts = App.accounts.filter(a => a.id !== acc.id);
            await App.save();
            App.openDuplicates();
            await App.render();
          });
          row.append(info, delBtn);
          groupWrap.appendChild(row);
        });
        content.appendChild(groupWrap);
      });
    }
    el('sheet-duplicates').classList.remove('hidden');
  },

  async exportData(encrypted = true) {
    if (App.accounts.length === 0) return Dialog.alert('Nothing to Export', 'You have no accounts to export.');

    if (encrypted) {
      Dialog.prompt('Encryption Password', 'Enter a strong password for this backup:', 'password', async (pwd) => {
        if (!pwd || pwd.length < 8) {
          if (pwd) App.toast('Password too short');
          return;
        }
        try {
          const salt = crypto.getRandomValues(new Uint8Array(16));
          const key = await CryptoUtils.deriveKeyFromPassword(pwd, salt);
          const json = JSON.stringify(App.accounts);
          const enc = await CryptoUtils.encryptWithKey(json, key);
          const payload = {
            v: 1,
            salt: bytesToBase64(salt),
            iv: enc.iv,
            ciphertext: enc.ciphertext
          };
          App._downloadJSON(payload, `modcore-encrypted-${Date.now()}.json`);
          App.toast('Encrypted backup downloaded');
        } catch {
          App.toast('Export failed');
        }
      });
    } else {
      Dialog.confirm('Plain Export', 'This export is NOT encrypted. Anyone with the file can access your secrets. Continue?', () => {
        App._downloadJSON(App.accounts, `modcore-backup-${Date.now()}.json`);
        App.toast('Plain backup downloaded');
      });
    }
  },

  _downloadJSON(obj, filename) {
    const blob = new Blob([JSON.stringify(obj, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = make('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  },

  importData() {
    const input = make('input');
    input.type = 'file'; input.accept = '.json,application/json';
    input.addEventListener('change', async (e) => {
      const file = e.target.files[0];
      if (!file) return;
      if (file.size > 10 * 1024 * 1024) return Dialog.alert('File Too Large', 'Backup must be under 10 MB.');
      const reader = new FileReader();
      reader.onload = async (r) => {
        try {
          const parsed = JSON.parse(r.target.result);
          if (parsed && parsed.ciphertext && parsed.iv && parsed.salt) {
            Dialog.prompt('Decryption Password', 'Enter the password for this encrypted backup:', 'password', async (pwd) => {
              if (!pwd) return;
              try {
                const salt = base64ToBytes(parsed.salt);
                const key = await CryptoUtils.deriveKeyFromPassword(pwd, salt);
                const dec = await CryptoUtils.decryptWithKey({ iv: parsed.iv, ciphertext: parsed.ciphertext }, key);
                App._doImport(JSON.parse(dec));
              } catch {
                Dialog.alert('Wrong Password', 'Could not decrypt. Check your password.');
              }
            });
          } else if (Array.isArray(parsed)) {
            App._doImport(parsed);
          } else {
            throw new Error('bad format');
          }
        } catch {
          Dialog.alert('Import Error', 'Invalid or corrupted backup file.');
        }
      };
      reader.readAsText(file);
    });
    input.click();
  },

  _validateImported(imported) {
    if (!Array.isArray(imported)) return [];
    const valid = [];
    for (const acc of imported) {
      if (!acc || typeof acc !== 'object') continue;
      if (typeof acc.issuer !== 'string' || !acc.issuer.trim()) continue;
      if (typeof acc.secret !== 'string') continue;
      const secret = acc.secret.replace(/\s+/g, '').toUpperCase();
      if (!Validators.isValidBase32(secret)) continue;

      valid.push({
        id: typeof acc.id === 'string' && acc.id ? acc.id : Date.now().toString(36) + Math.random().toString(36).slice(2),
        issuer: acc.issuer.trim(),
        account: typeof acc.account === 'string' ? acc.account : '',
        secret,
        algo: ['SHA-1', 'SHA-256', 'SHA-512'].includes(acc.algo) ? acc.algo : 'SHA-1',
        digits: Validators.isValidDigits(acc.digits) ? acc.digits : 6,
        period: Validators.isValidPeriod(acc.period) ? acc.period : 30,
        tags: Validators.sanitizeTags(acc.tags),
        pinned: !!acc.pinned,
        created: typeof acc.created === 'number' ? acc.created : Date.now(),
        lastUsed: typeof acc.lastUsed === 'number' ? acc.lastUsed : null,
        usageCount: typeof acc.usageCount === 'number' ? acc.usageCount : 0,
      });
    }
    return valid;
  },

  _doImport(imported) {
    const valid = App._validateImported(imported);
    if (valid.length === 0) {
      return Dialog.alert('Import Error', 'No valid accounts found in the backup.');
    }
    Dialog.confirm(
      'Import Mode',
      `Found ${valid.length} valid account${valid.length === 1 ? '' : 's'}. Replace all existing data or merge?`,
      async () => {
        App.accounts = valid;
        await App.save(); await App.render();
        App.toast(`Loaded ${valid.length} accounts`);
      },
      'Replace',
      async () => {
        const ids = new Set(App.accounts.map(a => a.id));
        const nov = valid.filter(a => !ids.has(a.id));
        App.accounts.push(...nov);
        await App.save(); await App.render();
        App.toast(`Merged ${nov.length} new accounts`);
      },
      'Merge'
    );
  },

  async render() {
    const listMain = el('token-list');
    const listPin = el('pinned-list');
    const secPin = el('pinned-section');
    const empty = el('empty-state');
    const secAll = el('all-accounts-section');

    listMain.textContent = '';
    listPin.textContent = '';

    const q = App.filter.trim().toLowerCase();
    let items = App.accounts.filter(a => {
      if (!q) return true;
      return (a.issuer + ' ' + (a.account || '')).toLowerCase().includes(q)
          || (a.tags || []).some(t => t.toLowerCase().includes(q));
    });

    if (App.sortMode === 'alpha') items.sort((a, b) => a.issuer.localeCompare(b.issuer));
    else if (App.sortMode === 'date') items.sort((a, b) => b.created - a.created);
    else if (App.sortMode === 'used') items.sort((a, b) => (b.usageCount || 0) - (a.usageCount || 0));

    const pinned = items.filter(a => a.pinned);
    const others = items.filter(a => !a.pinned);

    secPin.classList.toggle('hidden', pinned.length === 0);
    secAll.classList.toggle('hidden', others.length === 0 && pinned.length > 0);

    if (items.length === 0) {
      empty.classList.remove('hidden');
      if (App.accounts.length === 0) {
        el('empty-title').textContent = 'No Accounts Yet';
        el('empty-desc').innerHTML = 'Tap <strong>+</strong> to scan a QR code or add an account manually.';
      } else {
        el('empty-title').textContent = 'No Matches';
        el('empty-desc').textContent = 'Try a different search or tag.';
      }
    } else {
      empty.classList.add('hidden');
    }

    for (const acc of pinned) listPin.appendChild(await App.createRow(acc));
    for (const acc of others) listMain.appendChild(await App.createRow(acc));
  },

  async createRow(acc) {
    const wrap = make('div', { className: 'token-row', role: 'listitem', tabIndex: 0 });
    wrap.dataset.id = acc.id;

    if (App.isEditMode) {
      const handle = make('div', { className: 'drag-handle', title: 'Drag to reorder' });
      handle.draggable = true;
      handle.addEventListener('click', e => e.stopPropagation());
      handle.addEventListener('dragstart', (e) => {
        App._dragSrcEl = wrap;
        e.dataTransfer.effectAllowed = 'move';
        wrap.classList.add('dragging');
      });
      handle.addEventListener('dragend', () => {
        wrap.classList.remove('dragging');
        document.querySelectorAll('.token-row').forEach(r => r.classList.remove('drag-over'));
        
        const pinnedList = document.querySelector('#pinned-list');
        const pinnedIds = new Set(Array.from(pinnedList.querySelectorAll('.token-row')).map(r => r.dataset.id));
        const newOrder = [];
        
        document.querySelectorAll('.token-row').forEach(r => {
          const account = App.accounts.find(a => a.id === r.dataset.id);
          if (account) {
            account.pinned = pinnedIds.has(account.id);
            newOrder.push(account);
          }
        });
        if (newOrder.length === App.accounts.length) {
          App.accounts = newOrder;
          App.save();
          App.render();
        }
      });
      wrap.appendChild(handle);
      
      const spacer = make('div', { style: 'flex: 1' });
      wrap.appendChild(spacer);

      const editBtn = make('button', { className: 'list-btn small edit-btn-row', type: 'button', title: 'Edit this account' });
      editBtn.textContent = 'Edit';
      wrap.appendChild(editBtn);
    } else {
      const code = await TOTP.generate(acc.secret, acc.algo, acc.digits, acc.period);
      const nextCode = await TOTP.generate(acc.secret, acc.algo, acc.digits, acc.period, 1);
      const progress = TOTP.getProgress(acc.period);
      const rem = TOTP.getTimeRemaining(acc.period);
      const urgency = rem <= 5 ? 'urgent' : rem <= 10 ? 'warning' : '';

      const iconWrap = App.settings.showIcons ? App._makeProviderIcon(acc.issuer) : null;
      if (iconWrap) wrap.appendChild(iconWrap);

      const info = make('div', { className: 'token-info' });
      const h4 = make('h4'); h4.textContent = acc.issuer;
      const p = make('p'); p.textContent = acc.account || 'No account specified';
      info.append(h4, p);

      if (acc.pinned) {
        const pinBadge = make('span', { className: 'autofill-badge' });
        pinBadge.textContent = 'pinned';
        info.appendChild(pinBadge);
      }

      if (acc.tags?.length) {
        const tagsDiv = make('div', { className: 'tags-display' });
        acc.tags.forEach(t => {
          const chip = make('span', { className: 'tag-chip' });
          chip.textContent = '#' + t;
          tagsDiv.appendChild(chip);
        });
        info.appendChild(tagsDiv);
      }
      wrap.appendChild(info);

      const right = make('div', { className: 'token-right' });

      const half = Math.ceil(code.length / 2);
      const codeSpan = make('span', { className: `token-code ${urgency}` });
      codeSpan.textContent = code.slice(0, half) + ' ' + code.slice(half);
      if (App.settings.privacyMode) App._applyPrivacy(codeSpan);
      right.appendChild(codeSpan);

      const timeEl = make('span', { className: `time-remaining ${urgency}` });
      timeEl.textContent = `${rem}s`;
      right.appendChild(timeEl);

      if (App.settings.showNextCode) {
        const nextEl = make('div', { className: 'token-next' });
        nextEl.textContent = `Next: ${nextCode}`;
        if (App.settings.privacyMode) App._applyPrivacy(nextEl);
        right.appendChild(nextEl);
      }

      if (App.settings.showProgress) {
        const bar = make('div', { className: 'progress-bar' });
        const fill = make('div', { className: `progress-fill ${urgency}` });
        fill.style.width = `${progress}%`;
        bar.appendChild(fill);
        wrap.appendChild(bar);
      }

      wrap.appendChild(right);
    }

    const clickHandler = async () => {
      if (App.isEditMode) {
        App.openEdit(acc);
      } else {
        const code = await TOTP.generate(acc.secret, acc.algo, acc.digits, acc.period);
        const raw = code.replace(/\s/g, '');
        const success = await copyToClipboard(raw);
        if (!success) return App.toast('Copy failed');
        
        acc.lastUsed = Date.now();
        acc.usageCount = (acc.usageCount || 0) + 1;
        await App.save();

        wrap.style.transition = 'background .15s';
        wrap.style.background = 'var(--color-primary-container)';
        setTimeout(() => { wrap.style.background = ''; }, 400);

        App.toast(`Copied ${acc.issuer}`);

        if (App.settings.autoClear) {
          clearTimeout(App._clearTimer);
          App._clearTimer = setTimeout(() => {
            copyToClipboard('').catch(() => {});
          }, 30000);
        }
      }
    };
    wrap.addEventListener('click', clickHandler);
    wrap.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        clickHandler();
      }
    });

    if (App.isEditMode) {
      wrap.addEventListener('dragover', (e) => {
        e.preventDefault();
        e.dataTransfer.dropEffect = 'move';
        return false;
      });
      wrap.addEventListener('dragenter', () => wrap.classList.add('drag-over'));
      wrap.addEventListener('dragleave', () => wrap.classList.remove('drag-over'));
      wrap.addEventListener('drop', (e) => {
        e.stopPropagation();
        if (App._dragSrcEl && App._dragSrcEl !== wrap) {
          if (App._dragSrcEl.compareDocumentPosition(wrap) & Node.DOCUMENT_POSITION_FOLLOWING) {
            wrap.after(App._dragSrcEl);
          } else {
            wrap.before(App._dragSrcEl);
          }
        }
        return false;
      });
    }

    return wrap;
  },

  _applyPrivacy(node) {
    node.style.filter = 'blur(6px)';
    node.style.transition = 'filter .2s';
    node.addEventListener('mouseenter', () => { node.style.filter = 'none'; });
    node.addEventListener('mouseleave', () => { node.style.filter = 'blur(6px)'; });
  },

  _makeProviderIcon(issuer) {
    const wrap = make('div', { className: 'provider-icon' });
    const url = getFaviconUrl(issuer);
    if (url) {
      const img = make('img');
      img.alt = issuer;
      img.src = url;
      img.onerror = () => {
        if (wrap.contains(img)) wrap.removeChild(img);
        wrap.appendChild(App._makeAvatar(issuer));
        wrap.style.background = 'transparent';
      };
      wrap.appendChild(img);
    } else {
      wrap.appendChild(App._makeAvatar(issuer));
      wrap.style.background = 'transparent';
    }
    return wrap;
  },

  _makeAvatar(issuer) {
    const av = make('div', { className: 'provider-avatar' });
    av.style.background = getProviderColor(issuer);
    av.textContent = (String(issuer)[0] || '?').toUpperCase();
    return av;
  },

  async tick() {
    if (App.isEditMode || document.hidden || !App.cek) return;
    const rows = document.querySelectorAll('.token-row');
    for (const row of rows) {
      const acc = App.accounts.find(a => a.id === row.dataset.id);
      if (!acc) continue;

      const code = await TOTP.generate(acc.secret, acc.algo, acc.digits, acc.period);
      const next = await TOTP.generate(acc.secret, acc.algo, acc.digits, acc.period, 1);
      const prog = TOTP.getProgress(acc.period);
      const rem = TOTP.getTimeRemaining(acc.period);
      const urg = rem <= 5 ? 'urgent' : rem <= 10 ? 'warning' : '';
      const half = Math.ceil(code.length / 2);
      const fmt = code.slice(0, half) + ' ' + code.slice(half);

      const codeEl = row.querySelector('.token-code');
      const nextEl = row.querySelector('.token-next');
      const fillEl = row.querySelector('.progress-fill');
      const timeEl = row.querySelector('.time-remaining');

      if (codeEl) { codeEl.textContent = fmt; codeEl.className = `token-code ${urg}`; }
      if (nextEl) nextEl.textContent = `Next: ${next}`;
      if (fillEl) { fillEl.style.width = `${prog}%`; fillEl.className = `progress-fill ${urg}`; }
      if (timeEl) { timeEl.textContent = `${rem}s`; timeEl.className = `time-remaining ${urg}`; }
    }
  },

  openEdit(acc) {
    App.editingId = acc.id;
    App.editTags = [...(acc.tags || [])];

    el('edit-issuer').value = acc.issuer;
    el('edit-account').value = acc.account || '';
    el('display-created').textContent = new Date(acc.created).toLocaleDateString();
    el('display-last-used').textContent = acc.lastUsed ? new Date(acc.lastUsed).toLocaleDateString() : 'Never';
    el('display-usage-count').textContent = acc.usageCount || 0;
    el('pin-label').textContent = acc.pinned ? 'Unpin Account' : 'Pin Account';

    App.renderTags('edit');
    el('sheet-edit').classList.remove('hidden');
  },

  closeSheet(name) {
    el(`sheet-${name}`).classList.add('hidden');
    if (name === 'edit') { App.editingId = null; App.editTags = []; }
    if (name === 'add') { App.addTags = []; }
  },

  clearAddForm() {
    ['inp-issuer', 'inp-account', 'inp-secret'].forEach(id => { el(id).value = ''; });
    el('sel-algo').value = 'SHA-1';
    el('inp-digits').value = '6';
    el('inp-period').value = '30';
    App.addTags = []; App.renderTags('add');
    el('btn-save-account').disabled = true;
    el('btn-save-account').setAttribute('aria-disabled', 'true');
    el('advanced-options').classList.add('hidden');
    el('btn-toggle-advanced').textContent = 'Show Advanced Options ▾';
  },

  validateAddForm() {
    const ok = !!(el('inp-issuer').value.trim() && el('inp-secret').value.trim());
    el('btn-save-account').disabled = !ok;
    el('btn-save-account').setAttribute('aria-disabled', String(!ok));
  },

  toast(msg) {
    const t = el('toast');
    t.textContent = msg;
    t.classList.remove('hidden');
    clearTimeout(App._toastTimer);
    App._toastTimer = setTimeout(() => t.classList.add('hidden'), 2200);
  },

  bindKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
      if (['INPUT', 'TEXTAREA', 'SELECT'].includes(e.target.tagName)) {
        if (e.key === 'Escape') e.target.blur();
        return;
      }
      if ((e.metaKey || e.ctrlKey) && e.key === 'n') {
        e.preventDefault();
        App.clearAddForm();
        el('sheet-add').classList.remove('hidden');
      }
      if ((e.metaKey || e.ctrlKey) && e.key === 'f') {
        e.preventDefault();
        el('inp-search').focus();
      }
      if ((e.metaKey || e.ctrlKey) && e.key === ',') {
        e.preventDefault();
        el('sheet-settings').classList.remove('hidden');
      }
      if (e.key === 'Escape') {
        const open = document.querySelector('.sheet:not(.hidden)');
        if (open) open.classList.add('hidden');
      }
    });
  },

  bindEvents() {
    el('btn-unlock-passkey').addEventListener('click', () => App.unlockWithPasskey());
    el('btn-unlock-recovery').addEventListener('click', () => App.unlockWithRecovery());
    el('btn-setup-passkey').addEventListener('click', () => App.setupPasskey());

    el('btn-settings').addEventListener('click', () => el('sheet-settings').classList.remove('hidden'));
    el('btn-add-menu').addEventListener('click', () => { App.clearAddForm(); el('sheet-add').classList.remove('hidden'); });

    el('btn-edit-mode').addEventListener('click', (e) => {
      App.isEditMode = !App.isEditMode;
      e.currentTarget.textContent = App.isEditMode ? 'Done' : 'Edit';
      App.render();
    });

    document.querySelectorAll('.chip').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.chip').forEach(b => {
          b.classList.remove('active');
          b.setAttribute('aria-selected', 'false');
        });
        btn.classList.add('active');
        btn.setAttribute('aria-selected', 'true');
        App.sortMode = btn.dataset.sort;
        App.render();
      });
    });

    el('inp-search').addEventListener('input', (e) => { 
      App.filter = e.target.value; 
      el('btn-clear-search').classList.toggle('visible', !!App.filter);
      App.render(); 
    });

    el('btn-clear-search').addEventListener('click', () => {
      el('inp-search').value = '';
      App.filter = '';
      el('btn-clear-search').classList.remove('visible');
      App.render();
      el('inp-search').focus();
    });

    el('btn-cancel-add').addEventListener('click', () => App.closeSheet('add'));
    el('btn-save-account').addEventListener('click', () => App.addAccount());
    el('inp-issuer').addEventListener('input', () => App.validateAddForm());
    el('inp-secret').addEventListener('input', () => App.validateAddForm());

    el('btn-toggle-secret').addEventListener('click', () => {
      const inp = el('inp-secret');
      const ico = el('icon-secret-eye');
      const show = inp.type === 'password';
      inp.type = show ? 'text' : 'password';
      ico.className = show ? 'icon icon-eyeoff sm sub' : 'icon icon-eye sm sub';
    });

    el('inp-tags').addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ',') {
        e.preventDefault();
        App.addTag(e.target.value, 'add');
      }
    });
    el('inp-tags').addEventListener('blur', (e) => { if (e.target.value.trim()) App.addTag(e.target.value, 'add'); });

    el('btn-scan-screen').addEventListener('click', () => App.scanFromScreen());
    el('btn-scan-image').addEventListener('click', () => el('inp-file-scan').click());
    el('inp-file-scan').addEventListener('change', (e) => App.handleFileUpload(e));

    el('btn-toggle-advanced').addEventListener('click', () => {
      const adv = el('advanced-options');
      const btn = el('btn-toggle-advanced');
      const hidden = adv.classList.toggle('hidden');
      btn.textContent = hidden ? 'Show Advanced Options ▾' : 'Hide Advanced Options ▴';
    });

    el('btn-close-edit').addEventListener('click', async () => {
      if (App.editingId) {
        const acc = App.accounts.find(a => a.id === App.editingId);
        if (acc) {
          acc.issuer = el('edit-issuer').value.trim() || acc.issuer;
          acc.account = el('edit-account').value.trim();
          acc.tags = [...App.editTags];
          await App.save();
          await App.render();
        }
      }
      App.closeSheet('edit');
    });

    el('edit-inp-tags').addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ',') { e.preventDefault(); App.addTag(e.target.value, 'edit'); }
    });
    el('edit-inp-tags').addEventListener('blur', (e) => { if (e.target.value.trim()) App.addTag(e.target.value, 'edit'); });

    el('btn-delete-account').addEventListener('click', () => App.deleteAccount());
    el('btn-toggle-pin').addEventListener('click', () => App.togglePin());
    el('btn-share-code').addEventListener('click', () => App.shareCode());
    el('btn-copy-otp-url').addEventListener('click', () => App.copyOtpUrl());
    el('btn-reveal-secret').addEventListener('click', () => App.revealSecret());

    el('btn-close-duplicates').addEventListener('click', () => el('sheet-duplicates').classList.add('hidden'));

    el('btn-close-settings').addEventListener('click', () => el('sheet-settings').classList.add('hidden'));
    el('btn-open-display').addEventListener('click', () => el('sheet-settings-display').classList.remove('hidden'));
    el('btn-close-display').addEventListener('click', () => el('sheet-settings-display').classList.add('hidden'));
    el('btn-open-security').addEventListener('click', () => el('sheet-settings-security').classList.remove('hidden'));
    el('btn-close-security').addEventListener('click', () => el('sheet-settings-security').classList.add('hidden'));
    el('btn-open-data').addEventListener('click', () => el('sheet-settings-data').classList.remove('hidden'));
    el('btn-close-data').addEventListener('click', () => el('sheet-settings-data').classList.add('hidden'));

    el('btn-manage-passkeys').addEventListener('click', () => {
      el('sheet-manage-passkeys').classList.remove('hidden');
      App.renderManagePasskeys();
    });
    el('btn-close-manage-passkeys').addEventListener('click', () => el('sheet-manage-passkeys').classList.add('hidden'));
    el('btn-add-passkey').addEventListener('click', () => App.addNewPasskey());
    el('btn-reset-recovery').addEventListener('click', () => App.resetRecoveryCode());

    el('btn-export').addEventListener('click', () => App.exportData(true));
    el('btn-export-plain').addEventListener('click', () => App.exportData(false));
    el('btn-import').addEventListener('click', () => App.importData());
    el('btn-find-duplicates').addEventListener('click', () => App.openDuplicates());
    el('btn-delete-all').addEventListener('click', () => {
      Dialog.confirm('Delete ALL Accounts', `This will delete all ${App.accounts.length} accounts permanently. This cannot be undone.`, async () => {
        App.accounts = [];
        await App.save(); await App.render();
        App.toast('All accounts deleted');
      });
    });

    el('btn-lock-now').addEventListener('click', () => App.lockNow());

    // Close native dialog on backdrop click
    const dialog = el('app-dialog');
    dialog.addEventListener('click', (e) => {
      if (e.target === dialog) {
        dialog.close();
      }
    });

    for (const [id, key] of SETTING_MAP) {
      const node = el(id);
      if (!node) continue;
      node.addEventListener('change', async (e) => {
        App.settings[key] = e.target.checked;
        await chrome.storage.local.set({ [StorageKeys.SETTINGS]: App.settings });
        await App.render();
      });
    }
  }
};

const Dialog = {
  _show(title, bodyNode, buttons) {
    const dialog = el('app-dialog');
    el('dialog-title').textContent = title;
    const body = el('dialog-body');
    body.textContent = '';
    if (typeof bodyNode === 'string') {
      const p = make('p');
      p.textContent = bodyNode;
      body.appendChild(p);
    } else if (bodyNode) {
      body.appendChild(bodyNode);
    }

    const actions = el('dialog-actions');
    actions.textContent = '';
    buttons.forEach(({ label, action, bold, red }) => {
      const btn = make('button', { className: `dialog-btn${bold ? ' bold' : ''}${red ? ' red' : ''}`, type: 'button' });
      btn.textContent = label;
      btn.addEventListener('click', () => {
        dialog.close();
        if (action) action();
      });
      actions.appendChild(btn);
    });

    dialog.showModal();
  },

  alert(title, msg) {
    Dialog._show(title, msg, [{ label: 'OK', action: null, bold: true }]);
  },

  confirm(title, msg, onOk, okLabel = 'OK', onCancel = null, cancelLabel = 'Cancel') {
    Dialog._show(title, msg, [
      { label: cancelLabel, action: onCancel, bold: false },
      { label: okLabel, action: onOk, bold: true },
    ]);
  },

  custom(title, bodyNode, buttons) {
    Dialog._show(title, bodyNode, buttons);
  },

  prompt(title, msg, inputType = 'text', onSubmit) {
    const wrap = make('div');
    const p = make('p'); p.textContent = msg;
    p.style.cssText = 'margin:0 16px 12px;font-size:13px;color:var(--color-text-secondary);';
    const inpWrap = make('div');
    inpWrap.style.cssText = 'padding:0 16px 16px;';
    const inp = make('input');
    inp.type = inputType;
    inp.style.cssText = 'width:100%;padding:10px 14px;border-radius:24px;border:none;background:var(--color-surface-highest);color:var(--color-text-primary);font-size:15px;font-family:var(--font-sans);outline:none;';
    inp.placeholder = inputType === 'password' ? '••••••••' : '';
    inpWrap.appendChild(inp);
    wrap.append(p, inpWrap);

    Dialog._show(title, wrap, [
      { label: 'Cancel', action: null, bold: false },
      { label: 'OK', action: () => onSubmit(inp.value), bold: true },
    ]);
    setTimeout(() => inp.focus(), 50);
    inp.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        el('app-dialog').close();
        onSubmit(inp.value);
      }
    });
  }
};

document.addEventListener('DOMContentLoaded', () => App.init());
