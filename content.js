/* content.js */
'use strict';

(() => {
  const OTP_REGEX = /otp|2fa|two.factor|mfa|authenticator|verification|token|totp|passcode/i;
  const EXCLUDE_REGEX = /phone|tel|zip|postal|card|cvv|ssn|credit/i;

  let autofillHost = null;
  let hideTimeout = null;

  function isOtpInput(el) {
    if (el.tagName !== 'INPUT') return false;
    const type = el.getAttribute('type') || 'text';
    if (['hidden', 'submit', 'button', 'checkbox', 'radio', 'file', 'image'].includes(type)) return false;

    let score = 0;
    const attrs = ['name', 'id', 'placeholder', 'autocomplete', 'aria-label', 'class', 'data-testid'];
    for (const attr of attrs) {
      const val = (el.getAttribute(attr) || '').toLowerCase();
      if (OTP_REGEX.test(val)) score += 2;
      if (EXCLUDE_REGEX.test(val)) score -= 3;
    }

    if (el.autocomplete === 'one-time-code') score += 5;
    if (el.inputMode === 'numeric') score += 1;

    const maxLen = parseInt(el.getAttribute('maxlength')) || 0;
    if (maxLen >= 4 && maxLen <= 12) score += 2;
    if (maxLen > 20) score -= 2;

    const pattern = el.getAttribute('pattern') || '';
    if (/^\d+$/.test(pattern) || /^\d{4,8}$/.test(pattern)) score += 2;

    if (el.labels) {
      for (const label of el.labels) {
        const text = label.textContent.toLowerCase();
        if (OTP_REGEX.test(text)) score += 2;
        if (EXCLUDE_REGEX.test(text)) score -= 3;
      }
    }

    return score >= 3;
  }

  function createHost() {
    if (autofillHost) return autofillHost;
    const host = document.createElement('div');
    host.id = 'modcore-autofill-host';
    host.style.cssText = 'position:absolute;z-index:2147483647;display:none;';
    document.body.appendChild(host);

    const shadow = host.attachShadow({ mode: 'open' });
    const style = document.createElement('style');
    style.textContent = `
      .panel {
        background: #ffffff;
        border: 1px solid #0b57d0;
        border-radius: 12px;
        min-width: 240px;
        overflow: hidden;
        font-family: system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
      }
      .row {
        display: flex;
        align-items: center;
        justify-content: space-between;
        width: 100%;
        padding: 10px 14px;
        border: none;
        background: none;
        font-size: 14px;
        cursor: pointer;
        color: #1f2937;
        text-align: left;
      }
      .row:hover { background: #f0f4f9; }
      .row.recommended { font-weight: 600; color: #0b57d0; }
      .toggle {
        width: 100%;
        padding: 8px 14px;
        border: none;
        border-top: 1px solid #e5e7eb;
        background: #f9fafb;
        font-size: 12px;
        color: #6b7280;
        cursor: pointer;
        text-align: left;
      }
      .list { display: block; }
      .list.hidden { display: none; }
      .empty { padding: 12px; font-size: 13px; color: #6b7280; text-align: center; }
    `;
    shadow.appendChild(style);
    const panel = document.createElement('div');
    panel.className = 'panel';
    shadow.appendChild(panel);
    autofillHost = { host, panel, shadow };
    return autofillHost;
  }

  function fill(input, code) {
    input.focus();
    input.value = code;
    ['input', 'change', 'keyup'].forEach(evt => {
      input.dispatchEvent(new Event(evt, { bubbles: true }));
    });
    hidePanel();
  }

  function showPanel(input, codes) {
    const { host, panel } = createHost();
    const rect = input.getBoundingClientRect();
    host.style.top = `${rect.bottom + window.scrollY + 4}px`;
    host.style.left = `${rect.left + window.scrollX}px`;
    host.style.display = 'block';

    panel.textContent = '';
    const recommended = codes.find(c => c.recommended);
    const others = codes.filter(c => !c.recommended);

    if (recommended) {
      const btn = document.createElement('button');
      btn.className = 'row recommended';
      btn.textContent = `${recommended.issuer} — ${recommended.code}`;
      btn.addEventListener('mousedown', (e) => { e.preventDefault(); fill(input, recommended.code); });
      panel.appendChild(btn);
    }

    if (others.length > 0) {
      const toggle = document.createElement('button');
      toggle.className = 'toggle';
      toggle.textContent = `Other accounts (${others.length})`;
      panel.appendChild(toggle);

      const list = document.createElement('div');
      list.className = 'list hidden';
      others.forEach(o => {
        const btn = document.createElement('button');
        btn.className = 'row';
        btn.textContent = `${o.issuer} — ${o.code}`;
        btn.addEventListener('mousedown', (e) => { e.preventDefault(); fill(input, o.code); });
        list.appendChild(btn);
      });
      panel.appendChild(list);

      toggle.addEventListener('mousedown', (e) => {
        e.preventDefault();
        list.classList.toggle('hidden');
      });
    }

    if (!recommended && others.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'empty';
      empty.textContent = 'No matching accounts';
      panel.appendChild(empty);
    }
  }

  function hidePanel() {
    if (autofillHost) autofillHost.host.style.display = 'none';
  }

  document.addEventListener('focusin', async (e) => {
    if (!isOtpInput(e.target)) return;
    clearTimeout(hideTimeout);

    try {
      const res = await chrome.runtime.sendMessage({ type: 'GET_AUTOFILL_CODES' });
      if (res && res.codes && res.codes.length > 0) {
        showPanel(e.target, res.codes);
      }
    } catch {
      // Ignore
    }
  });

  document.addEventListener('focusout', (e) => {
    if (isOtpInput(e.target)) {
      hideTimeout = setTimeout(() => {
        if (!autofillHost || !autofillHost.host.contains(document.activeElement)) {
          hidePanel();
        }
      }, 200);
    }
  });
})();