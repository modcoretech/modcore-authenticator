/* js/content.js */
'use strict';

(() => {
  const OTP_REGEX = /otp|2fa|two.?factor|mfa|authenticator|verification|token|totp|passcode|one.?time/i;
  const EXCLUDE_REGEX = /phone|tel\b|zip|postal|card|cvv|ssn|credit|search|username|password/i;

  let autofillHost = null;
  let hideTimeout = null;
  let focusTimeout = null;
  let refreshInterval = null;
  let currentInput = null;

  function isOtpInput(el) {
    if (!el || el.tagName !== 'INPUT') return false;
    const type = (el.getAttribute('type') || 'text').toLowerCase();
    if (['hidden', 'submit', 'button', 'checkbox', 'radio', 'file', 'image', 'password', 'email', 'url', 'date'].includes(type)) return false;

    let score = 0;
    const attrs = ['name', 'id', 'placeholder', 'autocomplete', 'aria-label', 'class', 'data-testid', 'data-test', 'data-field', 'data-qa'];
    for (const attr of attrs) {
      const val = (el.getAttribute(attr) || '').toLowerCase();
      if (OTP_REGEX.test(val)) score += 2;
      if (EXCLUDE_REGEX.test(val)) score -= 3;
    }

    if ((el.getAttribute('autocomplete') || '').toLowerCase() === 'one-time-code') score += 6;
    if ((el.getAttribute('inputmode') || '').toLowerCase() === 'numeric') score += 1;

    const maxLen = parseInt(el.getAttribute('maxlength'), 10) || 0;
    if (maxLen >= 4 && maxLen <= 12) score += 2;
    if (maxLen > 20 || (maxLen > 0 && maxLen < 4)) score -= 2;

    const pattern = el.getAttribute('pattern') || '';
    if (/^\d+$/.test(pattern) || /^\d{4,8}$/.test(pattern)) score += 2;

    if (el.labels) {
      for (const label of el.labels) {
        const text = (label.textContent || '').toLowerCase();
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
    // Using fixed positioning on documentElement avoids layout/scroll context issues
    host.style.cssText = 'position:fixed;z-index:2147483647;display:none;';
    document.documentElement.appendChild(host);

    const shadow = host.attachShadow({ mode: 'open' });
    const style = document.createElement('style');
    style.textContent = `
      :host, * { box-sizing: border-box; }
      .panel {
        background: #15181e;
        color: #fbfdff;
        border-radius: 24px;
        width: 300px;
        overflow: hidden;
        font-family: 'Akt', system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
        box-shadow: 0 8px 32px rgba(0,0,0,0.55);
      }
      .row {
        display: flex; align-items: center; justify-content: space-between;
        width: 100%; padding: 12px 16px;
        border: none; background: none;
        font-size: 14px; cursor: pointer;
        color: inherit;
        text-align: left;
        font-family: inherit;
        gap: 12px;
      }
      .row:hover { background: #1c2028; }
      .row.recommended { font-weight: 600; color: #4a7fff; }
      .row .code { font-family: 'SFMono-Regular', Consolas, monospace; font-size: 15px; letter-spacing: 1.5px; }
      .row .issuer { font-weight: 500; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
      .row.account { color: #a0a8b8; font-size: 13px; padding: 9px 16px; }
      .toggle {
        width: 100%; padding: 10px 16px;
        border: none;
        border-top: 1px solid #22262f;
        background: #1c2028;
        font-size: 12px; color: #a0a8b8;
        cursor: pointer; text-align: left; font-family: inherit;
      }
      .list { display: block; }
      .list.hidden { display: none; }
      .empty { padding: 14px; font-size: 13px; color: #a0a8b8; text-align: center; }
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

  function positionPanel(input) {
    if (!autofillHost) return;
    const { host, panel } = autofillHost;
    
    // Show momentarily to measure its true width/height
    host.style.display = 'block';
    
    const panelRect = panel.getBoundingClientRect();
    const panelHeight = panelRect.height || 200;
    const panelWidth = panelRect.width || 300;
    
    const rect = input.getBoundingClientRect();
    const viewportHeight = window.innerHeight;
    const viewportWidth = window.innerWidth;
    
    // Vertical placement (prefer below)
    let top = rect.bottom + 8;
    if (top + panelHeight + 8 > viewportHeight) {
      // Not enough room below, place above
      top = rect.top - panelHeight - 8;
      // If it overflows the top, pin it to the top edge
      if (top < 8) {
        top = Math.max(8, viewportHeight - panelHeight - 8);
      }
    }
    
    // Horizontal placement
    let left = rect.left;
    if (left + panelWidth + 8 > viewportWidth) {
      left = viewportWidth - panelWidth - 8;
    }
    if (left < 8) {
      left = 8;
    }
    
    host.style.top = `${top}px`;
    host.style.left = `${left}px`;
  }

  function renderPanel(input, codes) {
    const { panel } = createHost();
    panel.textContent = '';

    const recommended = codes.filter(c => c.recommended);
    const others = codes.filter(c => !c.recommended);

    if (recommended.length > 0) {
      for (const rec of recommended) {
        const btn = document.createElement('button');
        btn.className = 'row recommended';
        const issuer = document.createElement('span');
        issuer.className = 'issuer';
        issuer.textContent = rec.issuer || 'Account';
        const code = document.createElement('span');
        code.className = 'code';
        code.textContent = rec.code;
        btn.append(issuer, code);
        btn.addEventListener('mousedown', (e) => {
          e.preventDefault();
          fill(input, rec.code);
        });
        panel.appendChild(btn);
      }
    }

    if (others.length > 0) {
      if (recommended.length > 0) {
        const toggle = document.createElement('button');
        toggle.className = 'toggle';
        toggle.textContent = `Other accounts (${others.length})`;
        panel.appendChild(toggle);

        const list = document.createElement('div');
        list.className = 'list hidden';

        others.forEach(o => {
          const btn = document.createElement('button');
          btn.className = 'row';
          const issuer = document.createElement('span');
          issuer.className = 'issuer';
          issuer.textContent = o.issuer || 'Account';
          const code = document.createElement('span');
          code.className = 'code';
          code.textContent = o.code;
          btn.append(issuer, code);
          btn.addEventListener('mousedown', (e) => {
            e.preventDefault();
            fill(input, o.code);
          });
          list.appendChild(btn);
        });
        panel.appendChild(list);

        toggle.addEventListener('mousedown', (e) => {
          e.preventDefault();
          list.classList.toggle('hidden');
          positionPanel(input);
        });
      } else {
        others.forEach(o => {
          const btn = document.createElement('button');
          btn.className = 'row';
          const issuer = document.createElement('span');
          issuer.className = 'issuer';
          issuer.textContent = o.issuer || 'Account';
          const code = document.createElement('span');
          code.className = 'code';
          code.textContent = o.code;
          btn.append(issuer, code);
          btn.addEventListener('mousedown', (e) => {
            e.preventDefault();
            fill(input, o.code);
          });
          panel.appendChild(btn);
        });
      }
    }

    if (recommended.length === 0 && others.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'empty';
      empty.textContent = 'No matching accounts';
      panel.appendChild(empty);
    }
  }

  function showPanel(input, codes) {
    const { host } = createHost();
    renderPanel(input, codes);
    positionPanel(input);
    
    clearInterval(refreshInterval);
    refreshInterval = setInterval(async () => {
      if (!autofillHost || autofillHost.host.style.display === 'none' || !currentInput || !document.contains(currentInput)) {
        clearInterval(refreshInterval);
        refreshInterval = null;
        return;
      }
      try {
        const res = await chrome.runtime.sendMessage({ type: 'GET_AUTOFILL_CODES' });
        if (res && Array.isArray(res.codes) && res.codes.length > 0) {
          renderPanel(currentInput, res.codes);
          positionPanel(currentInput);
        }
      } catch { /* ignore */ }
    }, 15000);
  }

  function hidePanel() {
    if (autofillHost) autofillHost.host.style.display = 'none';
    clearInterval(refreshInterval);
    refreshInterval = null;
    currentInput = null;
  }

  document.addEventListener('focusin', async (e) => {
    if (!isOtpInput(e.target)) return;
    clearTimeout(hideTimeout);
    clearTimeout(focusTimeout);
    currentInput = e.target;

    focusTimeout = setTimeout(async () => {
      if (document.activeElement !== currentInput) return;
      try {
        const res = await chrome.runtime.sendMessage({ type: 'GET_AUTOFILL_CODES' });
        if (res && Array.isArray(res.codes) && res.codes.length > 0) {
          showPanel(currentInput, res.codes);
        }
      } catch { /* ignore */ }
    }, 180);
  });

  document.addEventListener('focusout', (e) => {
    if (isOtpInput(e.target)) {
      clearTimeout(focusTimeout);
      hideTimeout = setTimeout(() => {
        const active = document.activeElement;
        if (!autofillHost || !autofillHost.host.contains(active)) {
          hidePanel();
        }
      }, 220);
    }
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && autofillHost && autofillHost.host.style.display !== 'none') {
      hidePanel();
    }
  }, true);

  document.addEventListener('mousedown', (e) => {
    if (autofillHost && autofillHost.host.style.display !== 'none') {
      if (!autofillHost.host.contains(e.target) && e.target !== currentInput) {
        hidePanel();
      }
    }
  }, true);

  window.addEventListener('resize', () => {
    if (currentInput && autofillHost && autofillHost.host.style.display !== 'none') {
      positionPanel(currentInput);
    }
  });
  window.addEventListener('scroll', () => {
    if (currentInput && autofillHost && autofillHost.host.style.display !== 'none') {
      positionPanel(currentInput);
    }
  }, { passive: true });
})();