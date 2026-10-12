/*
 * SecureVault - content script
 * Recibe {username, password} desde el popup y rellena el formulario de login
 * de la pagina activa. No lee ni exfiltra nada: solo escribe en los campos.
 */
(function () {
  if (window.__svContentLoaded) return;
  window.__svContentLoaded = true;

  function visible(el) {
    const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0 && getComputedStyle(el).visibility !== 'hidden';
  }

  function findLoginFields() {
    const pwFields = [...document.querySelectorAll('input[type="password"]')].filter(visible);
    if (!pwFields.length) return null;
    const pw = pwFields[0];
    // buscar el campo de usuario: el input de texto/email visible mas cercano antes de la contrasena
    const form = pw.closest('form') || document;
    const candidates = [...form.querySelectorAll('input[type="text"], input[type="email"], input:not([type])')]
      .filter(visible)
      .filter(i => {
        const hint = (i.name + ' ' + i.id + ' ' + i.autocomplete + ' ' + (i.placeholder || '')).toLowerCase();
        return !/search|buscar|captcha|code|otp|phone|tel/.test(hint);
      });
    let user = null;
    for (const c of candidates) {
      const pos = pw.compareDocumentPosition(c);
      if (pos & Node.DOCUMENT_POSITION_PRECEDING) user = c; // el ultimo que precede a la contrasena
    }
    if (!user && candidates.length) user = candidates[0];
    return { user, pw };
  }

  function setValue(input, value) {
    // compatible con React/Vue: usar el setter nativo y disparar eventos
    const proto = Object.getPrototypeOf(input);
    const setter = Object.getOwnPropertyDescriptor(proto, 'value')?.set
      || Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
    setter.call(input, value);
    input.dispatchEvent(new Event('input', { bubbles: true }));
    input.dispatchEvent(new Event('change', { bubbles: true }));
    input.focus();
  }

  chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg && msg.type === 'SV_FILL') {
      const fields = findLoginFields();
      if (!fields) { sendResponse({ ok: false, reason: 'No se encontro formulario de login en esta pagina' }); return true; }
      if (fields.user && msg.username) setValue(fields.user, msg.username);
      setValue(fields.pw, msg.password);
      sendResponse({ ok: true });
    }
    return true;
  });
})();
