/*
 * SecureVault PWA - logica de la aplicacion
 * Estado sensible SOLO en memoria. En localStorage se guarda:
 *   sv_wrapped : seed cifrada con la contrasena local (PBKDF2 + AES-GCM)
 *   sv_cache   : ultimo blob CIFRADO de la boveda (para modo offline)
 *   sv_server  : URL del servidor
 * Nunca se persisten la seed, las claves ni datos en claro.
 */
(function () {
'use strict';
const C = window.SecureVaultCrypto;
const $ = id => document.getElementById(id);

// ---- diagnostico visible (Safari/iPhone no tiene consola a la mano) ----
function fatalBanner(msg) {
  const d = document.createElement('div');
  d.style.cssText = 'position:fixed;top:0;left:0;right:0;z-index:99;background:#fff;color:#111;padding:14px 16px;font:14px -apple-system,Arial;border-bottom:3px solid #111';
  d.textContent = 'SecureVault no pudo iniciar: ' + msg;
  document.body.appendChild(d);
}
if (!C) {
  fatalBanner(window.SecureVaultCryptoError || 'Error desconocido al cargar el modulo de cifrado.');
  return;
}
window.addEventListener('error', e => {
  if (!document.querySelector('[data-sv-err]')) {
    const d = document.createElement('div');
    d.dataset.svErr = '1';
    d.style.cssText = 'position:fixed;bottom:0;left:0;right:0;z-index:99;background:#fff;color:#111;padding:10px 14px;font:12px monospace;border-top:2px solid #111';
    d.textContent = 'Error: ' + (e.message || e.type) + (e.filename ? ' [' + e.filename.split('/').pop() + ':' + e.lineno + ']' : '');
    document.body.appendChild(d);
  }
});

// Servidor por defecto: el mismo origen desde donde se cargo la PWA.
// En el PC sera https://localhost:8443 y en el celular https://IP-del-pc:8443,
// sin que el usuario configure nada.
const DEFAULT_SERVER = (location.protocol === 'https:' ? location.origin : 'https://localhost:8443');
const LOCK_MINUTES = 10;

// ---------- estado en memoria (se borra al bloquear) ----------
let session = null; // { mnemonic, keys, vault }
let editingId = null;
let lockTimer = null;

// ---------- navegacion ----------
const screens = ['screen-welcome','screen-create','screen-verify','screen-import','screen-password','screen-unlock','screen-main'];
function show(id) {
  screens.forEach(s => $(s).classList.toggle('hidden', s !== id));
  window.scrollTo(0, 0);
}
document.querySelectorAll('[data-nav]').forEach(b => b.addEventListener('click', () => show(b.dataset.nav)));

function toast(msg, ms = 2200) {
  const t = $('toast');
  t.textContent = msg;
  t.classList.remove('hidden');
  clearTimeout(t._h);
  t._h = setTimeout(() => t.classList.add('hidden'), ms);
}

// ---------- almacenamiento local ----------
const store = {
  get wrapped() { const v = localStorage.getItem('sv_wrapped'); return v ? JSON.parse(v) : null; },
  set wrapped(v) { v ? localStorage.setItem('sv_wrapped', JSON.stringify(v)) : localStorage.removeItem('sv_wrapped'); },
  get cache() { const v = localStorage.getItem('sv_cache'); return v ? JSON.parse(v) : null; },
  set cache(v) { v ? localStorage.setItem('sv_cache', JSON.stringify(v)) : localStorage.removeItem('sv_cache'); },
  get server() {
    const saved = localStorage.getItem('sv_server');
    if (!saved) return DEFAULT_SERVER;
    // auto-correccion: "localhost" guardado no tiene sentido fuera del propio equipo
    if (saved.includes('localhost') && !DEFAULT_SERVER.includes('localhost')) return DEFAULT_SERVER;
    return saved;
  },
  set server(v) { localStorage.setItem('sv_server', v); }
};

// ---------- servidor ----------
async function api(method, path, body, token) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['X-Auth-Token'] = token;
  const res = await fetch(store.server + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const data = await res.json().catch(() => ({}));
  return { status: res.status, data };
}

function setSync(state) {
  const el = $('sync-status');
  el.classList.toggle('ok', state === 'ok');
  el.textContent = state === 'ok' ? 'sincronizado' : state === 'offline' ? 'offline' : state === 'pending' ? 'pendiente' : state;
}

// Sube la boveda actual cifrada. Si no hay red, deja el cache marcado como pendiente.
async function pushVault() {
  const payload = await C.encryptVault(session.vault, session.keys);
  store.cache = { vaultId: session.keys.vaultId, payload, pending: true };
  try {
    const r = await api('PUT', '/api/vault/' + session.keys.vaultId, payload, session.keys.authToken);
    if (r.status === 200) { store.cache = { vaultId: session.keys.vaultId, payload, pending: false }; setSync('ok'); return true; }
    if (r.status === 409) {
      // hay version mas reciente en el servidor: traerla, fusionar por id y reintentar
      await pullVault(true);
      return pushVault();
    }
    setSync('pending'); return false;
  } catch (e) { setSync('offline'); return false; }
}

// Descarga la boveda del servidor si es mas nueva que la copia local.
async function pullVault(merge = false) {
  try {
    const r = await api('GET', '/api/vault/' + session.keys.vaultId);
    if (r.status === 404) { setSync('ok'); return; }
    if (r.status !== 200) { setSync('pending'); return; }
    const remote = C.normalizeVault(await C.decryptVault(r.data.payload, keys));
    session.vault = merge ? C.mergeVaults(session.vault, remote) : remote;
    store.cache = { vaultId: session.keys.vaultId, payload: r.data.payload, pending: false };
    setSync('ok');
  } catch (e) { setSync('offline'); }
}

// ---------- sesion / bloqueo ----------
async function openSession(mnemonic) {
  const seed = await C.mnemonicToSeed(mnemonic);
  const keys = await C.deriveKeys(seed);
  session = { mnemonic: mnemonic.trim().toLowerCase().split(/\s+/).join(' '), keys, vault: { entries: [] } };

  // 1) cache local cifrado (funciona offline)
  const cache = store.cache;
  if (cache && cache.vaultId === keys.vaultId) {
    try { session.vault = C.normalizeVault(await C.decryptVault(cache.payload, keys)); } catch (e) { /* cache de otra seed o corrupto */ }
  }
  // 2) FUSIONAR con la version del servidor: nunca se pierde nada.
  // Union de credenciales de todos los dispositivos; en conflicto sobre la
  // MISMA credencial gana la edicion mas reciente; las eliminaciones
  // intencionales se respetan mediante lapidas.
  try {
    const r = await api('GET', '/api/vault/' + keys.vaultId);
    if (r.status === 200) {
      const remote = C.normalizeVault(await C.decryptVault(r.data.payload, keys));
      const merged = C.mergeVaults(session.vault, remote);
      session.vault = merged;
      if (C.vaultSignature(merged) !== C.vaultSignature(remote)) {
        // lo fusionado tiene algo que el servidor no conocia: subirlo
        await pushVault();
      } else {
        store.cache = { vaultId: keys.vaultId, payload: r.data.payload, pending: false };
        setSync('ok');
      }
    } else if (r.status === 404) {
      // el servidor no tiene la boveda (p. ej. se reinstalo el programa):
      // si este dispositivo tiene credenciales, se restauran automaticamente
      if (session.vault.entries.length > 0) await pushVault();
      else setSync('ok');
    }
  } catch (e) { setSync('offline'); }

  renderEntries();
  show('screen-main');
  armLockTimer();
}

function lock() {
  session = null; // las claves salen de memoria
  clearTimeout(lockTimer);
  if (store.wrapped) { $('unlock-password').value = ''; show('screen-unlock'); }
  else show('screen-welcome');
}

function armLockTimer() {
  clearTimeout(lockTimer);
  lockTimer = setTimeout(() => { toast('Bloqueado por inactividad'); lock(); }, LOCK_MINUTES * 60 * 1000);
}
['click','keydown','touchstart'].forEach(ev =>
  document.addEventListener(ev, () => { if (session) armLockTimer(); }, { passive: true }));

// ---------- onboarding: crear ----------
let pendingMnemonic = null;
let verifyIdx = [];

async function renderNewSeed() {
  pendingMnemonic = await C.generateMnemonic();
  const grid = $('seed-grid');
  grid.innerHTML = '';
  pendingMnemonic.split(' ').forEach(w => {
    const li = document.createElement('li');
    li.textContent = w;
    grid.appendChild(li);
  });
  $('chk-seed-saved').checked = false;
  $('btn-seed-continue').disabled = true;
}

$('btn-go-create').addEventListener('click', async () => { await renderNewSeed(); show('screen-create'); });
$('btn-regen-seed').addEventListener('click', renderNewSeed);
$('btn-copy-seed').addEventListener('click', async () => {
  await copySecret(pendingMnemonic, 'Seed copiada. Borrala del portapapeles cuando termines.');
});
$('chk-seed-saved').addEventListener('change', e => $('btn-seed-continue').disabled = !e.target.checked);

$('btn-seed-continue').addEventListener('click', () => {
  // pedir 3 palabras al azar para verificar la copia en papel
  const idx = new Set();
  while (idx.size < 3) idx.add(Math.floor(Math.random() * 24));
  verifyIdx = [...idx].sort((a, b) => a - b);
  const wrap = $('verify-fields');
  wrap.innerHTML = '';
  verifyIdx.forEach(i => {
    const label = document.createElement('label');
    label.textContent = 'Palabra #' + (i + 1);
    const input = document.createElement('input');
    input.type = 'text'; input.autocomplete = 'off'; input.spellcheck = false;
    input.dataset.idx = i;
    wrap.appendChild(label); wrap.appendChild(input);
  });
  $('verify-error').classList.add('hidden');
  show('screen-verify');
});

$('btn-verify').addEventListener('click', () => {
  const words = pendingMnemonic.split(' ');
  const ok = [...$('verify-fields').querySelectorAll('input')].every(inp =>
    inp.value.trim().toLowerCase() === words[inp.dataset.idx]);
  if (!ok) { $('verify-error').classList.remove('hidden'); return; }
  show('screen-password');
});

// ---------- onboarding: importar ----------
$('btn-go-import').addEventListener('click', () => { $('import-seed').value = ''; $('import-error').classList.add('hidden'); show('screen-import'); });
$('btn-import').addEventListener('click', async () => {
  const val = $('import-seed').value;
  const check = await C.validateMnemonic(val);
  if (!check.valid) {
    $('import-error').textContent = check.reason;
    $('import-error').classList.remove('hidden');
    return;
  }
  pendingMnemonic = val.trim().toLowerCase().split(/\s+/).join(' ');
  show('screen-password');
});

// ---------- contrasena local ----------
$('btn-set-password').addEventListener('click', async () => {
  const p1 = $('pw-new').value, p2 = $('pw-confirm').value;
  const err = $('pw-error');
  if (p1.length < 8) { err.textContent = 'Minimo 8 caracteres.'; err.classList.remove('hidden'); return; }
  if (p1 !== p2) { err.textContent = 'Las contrasenas no coinciden.'; err.classList.remove('hidden'); return; }
  err.classList.add('hidden');
  $('btn-set-password').textContent = 'Derivando claves…';
  store.wrapped = await C.wrapSeedWithPassword(pendingMnemonic, p1);
  const m = pendingMnemonic; pendingMnemonic = null;
  $('pw-new').value = ''; $('pw-confirm').value = '';
  await openSession(m);
  $('btn-set-password').textContent = 'Guardar y entrar';
});

// ---------- desbloqueo ----------
$('btn-unlock').addEventListener('click', async () => {
  const err = $('unlock-error');
  err.classList.add('hidden');
  $('btn-unlock').textContent = 'Verificando…';
  try {
    const mnemonic = await C.unwrapSeedWithPassword(store.wrapped, $('unlock-password').value);
    await openSession(mnemonic);
  } catch (e) {
    err.textContent = 'Contrasena incorrecta.';
    err.classList.remove('hidden');
  }
  $('btn-unlock').textContent = 'Desbloquear';
});
$('unlock-password').addEventListener('keydown', e => { if (e.key === 'Enter') $('btn-unlock').click(); });
$('btn-unlock-seed').addEventListener('click', () => show('screen-import'));
$('btn-forget-device').addEventListener('click', () => {
  if (!confirm('Se borraran la contrasena local y la copia cifrada de este dispositivo. La boveda del servidor NO se elimina y podras volver a abrirla con tu seed. Continuar?')) return;
  store.wrapped = null; store.cache = null;
  show('screen-welcome');
});

// ---------- lista de credenciales ----------
function renderEntries() {
  const q = $('search').value.trim().toLowerCase();
  const list = $('entry-list');
  list.innerHTML = '';
  const entries = session.vault.entries
    .filter(e => !q || (e.name + ' ' + e.username + ' ' + e.url).toLowerCase().includes(q))
    .sort((a, b) => a.name.localeCompare(b.name));
  $('empty-state').classList.toggle('hidden', session.vault.entries.length > 0);
  for (const e of entries) {
    const li = document.createElement('li');
    li.className = 'entry';
    const info = document.createElement('div');
    info.className = 'info';
    info.innerHTML = '<div class="name"></div><div class="sub"></div>';
    info.querySelector('.name').textContent = e.name || '(sin nombre)';
    info.querySelector('.sub').textContent = e.username + (e.url ? '  ·  ' + e.url.replace(/^https?:\/\//, '') : '');
    const actions = document.createElement('div');
    actions.className = 'actions';
    const ICON_USER = '<svg viewBox="0 0 16 16" width="15" height="15" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="8" cy="5.5" r="2.6"/><path d="M2.8 13.5c.7-2.6 2.8-3.8 5.2-3.8s4.5 1.2 5.2 3.8"/></svg>';
    const ICON_KEY = '<svg viewBox="0 0 16 16" width="15" height="15" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><circle cx="5" cy="11" r="2.6"/><path d="M7 9l6.2-6.2M11 5l2 2M9 7l1.6 1.6"/></svg>';
    const bu = document.createElement('button');
    bu.className = 'icon-btn'; bu.title = 'Copiar usuario'; bu.innerHTML = ICON_USER;
    bu.addEventListener('click', ev => { ev.stopPropagation(); copySecret(e.username, 'Usuario copiado'); });
    const bp = document.createElement('button');
    bp.className = 'icon-btn'; bp.title = 'Copiar contrasena'; bp.innerHTML = ICON_KEY;
    bp.addEventListener('click', ev => { ev.stopPropagation(); copySecret(e.password, 'Contrasena copiada (se limpia en 30 s)'); });
    actions.appendChild(bu); actions.appendChild(bp);
    li.appendChild(info); li.appendChild(actions);
    li.addEventListener('click', () => openEntryModal(e.id));
    list.appendChild(li);
  }
}
$('search').addEventListener('input', renderEntries);

async function copySecret(text, msg) {
  try {
    await navigator.clipboard.writeText(text);
  } catch (e) {
    // fallback para Safari antiguo: seleccion + execCommand
    const ta = document.createElement('textarea');
    ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.focus(); ta.select();
    try { document.execCommand('copy'); } catch (e2) {}
    document.body.removeChild(ta);
  }
  toast(msg);
  // limpieza del portapapeles a los 30 s (donde el navegador lo permita)
  setTimeout(async () => {
    try {
      if (navigator.clipboard.readText && await navigator.clipboard.readText() === text) {
        await navigator.clipboard.writeText('');
      }
    } catch (e) {}
  }, 30000);
}

// ---------- modal de entrada ----------
function openEntryModal(id) {
  editingId = id || null;
  $('entry-modal-title').textContent = id ? 'Editar credencial' : 'Nueva credencial';
  $('btn-delete-entry').classList.toggle('hidden', !id);
  const e = id ? session.vault.entries.find(x => x.id === id) : { name: '', url: '', username: '', password: '', notes: '' };
  $('f-name').value = e.name; $('f-url').value = e.url;
  $('f-username').value = e.username; $('f-password').value = e.password;
  $('f-notes').value = e.notes;
  $('f-password').type = 'password';
  $('modal-entry').classList.remove('hidden');
}
$('btn-add').addEventListener('click', () => openEntryModal(null));
$('btn-cancel-entry').addEventListener('click', () => $('modal-entry').classList.add('hidden'));
$('btn-toggle-pw').addEventListener('click', () => {
  const f = $('f-password');
  f.type = f.type === 'password' ? 'text' : 'password';
});
$('btn-gen-pw').addEventListener('click', () => {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!#$%&*+-?@';
  const bytes = C.randomBytes(20);
  $('f-password').value = [...bytes].map(b => chars[b % chars.length]).join('');
  $('f-password').type = 'text';
});

$('btn-save-entry').addEventListener('click', async () => {
  const name = $('f-name').value.trim();
  if (!name) { toast('El nombre es obligatorio'); return; }
  const data = {
    name,
    url: $('f-url').value.trim(),
    username: $('f-username').value.trim(),
    password: $('f-password').value,
    notes: $('f-notes').value.trim()
  };
  if (editingId) {
    Object.assign(session.vault.entries.find(x => x.id === editingId), data, { updatedAt: Date.now() });
  } else {
    session.vault.entries.push({ id: C.bytesToHex(C.randomBytes(8)), createdAt: Date.now(), updatedAt: Date.now(), ...data });
  }
  $('modal-entry').classList.add('hidden');
  renderEntries();
  toast('Guardado');
  pushVault();
});

$('btn-delete-entry').addEventListener('click', async () => {
  if (!confirm('Eliminar esta credencial?')) return;
  session.vault.deleted = session.vault.deleted || {};
  session.vault.deleted[editingId] = Date.now(); // lapida: evita que reaparezca al fusionar
  session.vault.entries = session.vault.entries.filter(x => x.id !== editingId);
  $('modal-entry').classList.add('hidden');
  renderEntries();
  pushVault();
});

// ---------- menu / drawer ----------
$('btn-menu').addEventListener('click', () => {
  $('server-label').textContent = store.server.replace(/^https:\/\//, '');
  $('drawer').classList.remove('hidden');
});
$('btn-close-drawer').addEventListener('click', () => $('drawer').classList.add('hidden'));
$('btn-lock').addEventListener('click', lock);
$('btn-sync-now').addEventListener('click', async () => { await pullVault(true); await pushVault(); renderEntries(); toast('Sincronizacion completa'); });

// compartir acceso con codigo QR: la camara del celular abre el link directo
$('btn-share').addEventListener('click', async () => {
  let shareUrl = store.server;
  // si estamos en localhost, pedir al servidor su IP en la red para que el QR sirva en celulares
  if (shareUrl.includes('localhost') || shareUrl.includes('127.0.0.1')) {
    try {
      const r = await api('GET', '/api/info');
      if (r.status === 200 && r.data.ips && r.data.ips.length) {
        shareUrl = 'https://' + r.data.ips[0] + ':' + r.data.port;
      }
    } catch (e) {}
  }
  const qr = qrcode(0, 'M');
  qr.addData(shareUrl);
  qr.make();
  $('qr-box').innerHTML = qr.createSvgTag({ cellSize: 6, margin: 0 });
  $('share-link').textContent = shareUrl;
  $('drawer').classList.add('hidden');
  $('modal-share').classList.remove('hidden');
});
$('btn-close-share').addEventListener('click', () => $('modal-share').classList.add('hidden'));

// ---------- extension de Chrome ----------
$('btn-get-extension').addEventListener('click', () => {
  $('drawer').classList.add('hidden');
  $('modal-extension').classList.remove('hidden');
});
$('btn-close-extension').addEventListener('click', () => $('modal-extension').classList.add('hidden'));
$('btn-download-ext').addEventListener('click', () => {
  const a = document.createElement('a');
  a.href = store.server + '/extension.zip';
  a.download = 'securevault-extension.zip';
  a.click();
  toast('Descargando extension…');
});
$('btn-show-server').addEventListener('click', () => {
  const v = prompt('URL del servidor SecureVault:', store.server);
  if (v) { store.server = v.replace(/\/$/, ''); $('server-label').textContent = store.server.replace(/^https:\/\//, ''); }
});

// exportar / importar backup .svault (siempre cifrado)
$('btn-export').addEventListener('click', async () => {
  const payload = await C.encryptVault(session.vault, session.keys);
  const blob = new Blob([JSON.stringify({ format: 'svault', v: 1, vaultId: session.keys.vaultId, payload }, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'securevault-backup-' + new Date().toISOString().slice(0, 10) + '.svault';
  a.click();
  URL.revokeObjectURL(a.href);
  toast('Backup exportado (cifrado)');
});
$('btn-import-backup').addEventListener('click', () => $('file-import').click());
$('file-import').addEventListener('change', async e => {
  const file = e.target.files[0];
  if (!file) return;
  try {
    const data = JSON.parse(await file.text());
    if (data.format !== 'svault') throw new Error('Formato invalido');
    const imported = await C.decryptVault(data.payload, session.keys); // solo abre si es de la misma seed
    session.vault = C.mergeVaults(session.vault, imported);
    renderEntries();
    pushVault();
    toast('Backup importado y fusionado');
  } catch (err) {
    toast('No se pudo importar: el backup no corresponde a esta seed o esta danado');
  }
  e.target.value = '';
});

// eliminacion definitiva (requiere reescribir la seed)
$('btn-delete-vault').addEventListener('click', () => {
  $('confirm-seed-input').value = '';
  $('confirm-seed-error').classList.add('hidden');
  $('drawer').classList.add('hidden');
  $('modal-confirm-seed').classList.remove('hidden');
});
$('btn-cancel-delete').addEventListener('click', () => $('modal-confirm-seed').classList.add('hidden'));
$('btn-confirm-delete').addEventListener('click', async () => {
  const typed = $('confirm-seed-input').value.trim().toLowerCase().split(/\s+/).join(' ');
  if (typed !== session.mnemonic) {
    $('confirm-seed-error').textContent = 'La seed no coincide.';
    $('confirm-seed-error').classList.remove('hidden');
    return;
  }
  try { await api('DELETE', '/api/vault/' + session.keys.vaultId, null, session.keys.authToken); } catch (e) {}
  store.wrapped = null; store.cache = null;
  session = null;
  $('modal-confirm-seed').classList.add('hidden');
  toast('Boveda eliminada definitivamente');
  show('screen-welcome');
});

// ---------- arranque ----------
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('sw.js').catch(() => {});
}
window.addEventListener('online', () => { if (session) { pushVault(); } });

// ---------- tutorial "agregar a pantalla de inicio" ----------
function showInstallTutorial(platform) {
  // platform: 'ios' | 'android' | null (null = ambas pestanas visibles, se detecta la actual)
  const ua = navigator.userAgent || '';
  const detected = /iPhone|iPad|iPod/.test(ua) ? 'ios' : /Android/.test(ua) ? 'android' : 'ios';
  const p = platform || detected;
  $('install-ios').classList.toggle('hidden', p !== 'ios');
  $('install-android').classList.toggle('hidden', p !== 'android');
  $('modal-install').classList.remove('hidden');
}
$('tab-ios').addEventListener('click', () => showInstallTutorial('ios'));
$('tab-android').addEventListener('click', () => showInstallTutorial('android'));
$('btn-close-install').addEventListener('click', () => $('modal-install').classList.add('hidden'));

// boton permanente en el menu de opciones
$('btn-install-tutorial').addEventListener('click', () => {
  $('drawer').classList.add('hidden');
  showInstallTutorial(null);
});

// invitacion automatica en celulares mientras no este instalada
// (en modo instalado desaparece sola)
(function mobileInstallPrompt() {
  const ua = navigator.userAgent || '';
  const isIOS = /iPhone|iPad|iPod/.test(ua);
  const isAndroid = /Android/.test(ua);
  const standalone = window.matchMedia('(display-mode: standalone)').matches || window.navigator.standalone === true;
  if ((!isIOS && !isAndroid) || standalone) return;
  $('install-banner').classList.remove('hidden');
  $('btn-install-how').addEventListener('click', () => showInstallTutorial(null));
  $('btn-install-close').addEventListener('click', () => $('install-banner').classList.add('hidden'));
})();

if (store.wrapped) show('screen-unlock');
else show('screen-welcome');

})();
