/*
 * SecureVault - popup de la extension (MV3)
 * chrome.storage.local  : seed envuelta con contrasena (PBKDF2) + cache CIFRADO de la boveda
 * chrome.storage.session: mnemonic de la sesion activa (solo memoria, se borra al cerrar Chrome)
 * El descifrado ocurre aqui, en el popup. Nada en claro toca el disco.
 */
(function () {
'use strict';
const C = self.SecureVaultCrypto;
const $ = id => document.getElementById(id);
const SERVER = 'https://localhost:8443';
const LOCK_MS = 10 * 60 * 1000;

let session = null; // { keys, vault }
let currentDomain = '';

function view(id) {
  ['v-setup', 'v-lock', 'v-main'].forEach(v => $(v).classList.toggle('hidden', v !== id));
}
function err(id, msg) {
  const el = $(id);
  if (!msg) { el.classList.add('hidden'); return; }
  el.textContent = msg;
  el.classList.remove('hidden');
}

const storage = {
  get: keys => new Promise(r => chrome.storage.local.get(keys, r)),
  set: obj => new Promise(r => chrome.storage.local.set(obj, r)),
  clear: () => new Promise(r => chrome.storage.local.clear(r)),
  sGet: keys => new Promise(r => chrome.storage.session.get(keys, r)),
  sSet: obj => new Promise(r => chrome.storage.session.set(obj, r)),
  sClear: () => new Promise(r => chrome.storage.session.clear(r))
};

// ---------- sincronizacion con el servidor ----------
async function pull(keys) {
  try {
    const res = await fetch(SERVER + '/api/vault/' + keys.vaultId);
    if (res.status === 200) {
      const { payload } = await res.json();
      const local = (await storage.get('sv_cache')).sv_cache;
      if (!local || local.vaultId !== keys.vaultId || payload.updatedAt >= local.payload.updatedAt) {
        await storage.set({ sv_cache: { vaultId: keys.vaultId, payload } });
      }
    }
  } catch (e) { /* offline: se usa el cache cifrado */ }
}

async function loadVault(keys) {
  const { sv_cache } = await storage.get('sv_cache');
  if (sv_cache && sv_cache.vaultId === keys.vaultId) {
    try { return await C.decryptVault(sv_cache.payload, keys); } catch (e) {}
  }
  return { entries: [] };
}

// ---------- sesion ----------
async function openSession(mnemonic) {
  const seed = await C.mnemonicToSeed(mnemonic);
  const keys = await C.deriveKeys(seed);
  await pull(keys);
  const vault = await loadVault(keys);
  session = { keys, vault };
  await storage.sSet({ sv_session: { mnemonic, unlockedAt: Date.now() } });
  await renderMain();
  view('v-main');
}

async function lock() {
  session = null;
  await storage.sClear();
  view('v-lock');
}

// ---------- vista principal ----------
function domainMatch(entryUrl, domain) {
  if (!entryUrl) return false;
  try {
    const host = new URL(entryUrl.startsWith('http') ? entryUrl : 'https://' + entryUrl).hostname;
    return host === domain || host.endsWith('.' + domain) || domain.endsWith('.' + host);
  } catch (e) { return false; }
}

async function renderMain() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const tab = tabs[0];
  try { currentDomain = new URL(tab.url).hostname; } catch (e) { currentDomain = ''; }
  $('m-domain').textContent = currentDomain || 'sin sitio activo';

  const matching = session.vault.entries.filter(e => domainMatch(e.url, currentDomain));
  const others = session.vault.entries.filter(e => !matching.includes(e));
  const list = $('m-list');
  list.innerHTML = '';
  $('m-empty').classList.toggle('hidden', matching.length > 0);

  const make = (e, canFill) => {
    const li = document.createElement('li');
    li.className = 'entry';
    const info = document.createElement('div');
    info.className = 'info';
    info.innerHTML = '<div class="nm"></div><div class="us"></div>';
    info.querySelector('.nm').textContent = e.name;
    info.querySelector('.us').textContent = e.username;
    li.appendChild(info);
    const btns = document.createElement('div');
    btns.className = 'rowbtn';
    if (canFill) {
      const bf = document.createElement('button');
      bf.className = 'mini'; bf.textContent = 'Rellenar';
      bf.addEventListener('click', () => fill(tab.id, e));
      btns.appendChild(bf);
    }
    const bc = document.createElement('button');
    bc.className = 'mini'; bc.title = 'Copiar contrasena'; bc.textContent = '⁕';
    bc.addEventListener('click', async () => { await navigator.clipboard.writeText(e.password); bc.textContent = 'ok'; setTimeout(() => bc.textContent = '⁕', 900); });
    btns.appendChild(bc);
    li.appendChild(btns);
    return li;
  };

  matching.forEach(e => list.appendChild(make(e, true)));
  others.sort((a, b) => a.name.localeCompare(b.name)).forEach(e => list.appendChild(make(e, false)));
}

async function fill(tabId, entry) {
  try {
    await chrome.tabs.sendMessage(tabId, { type: 'SV_FILL', username: entry.username, password: entry.password });
    window.close();
  } catch (e) {
    // el content script puede no estar inyectado (pestana abierta antes de instalar): inyectar y reintentar
    await chrome.scripting.executeScript({ target: { tabId }, files: ['content.js'] });
    await chrome.tabs.sendMessage(tabId, { type: 'SV_FILL', username: entry.username, password: entry.password });
    window.close();
  }
}

// ---------- setup ----------
$('s-go').addEventListener('click', async () => {
  err('s-err', null);
  const seedVal = $('s-seed').value;
  const pw = $('s-pw').value;
  const check = await C.validateMnemonic(seedVal);
  if (!check.valid) { err('s-err', check.reason); return; }
  if (pw.length < 8) { err('s-err', 'La contrasena local necesita minimo 8 caracteres.'); return; }
  $('s-go').textContent = 'Derivando claves…';
  const mnemonic = seedVal.trim().toLowerCase().split(/\s+/).join(' ');
  const wrapped = await C.wrapSeedWithPassword(mnemonic, pw);
  await storage.set({ sv_wrapped: wrapped });
  await openSession(mnemonic);
  $('s-go').textContent = 'Vincular navegador';
});

// ---------- desbloqueo ----------
$('l-go').addEventListener('click', async () => {
  err('l-err', null);
  $('l-go').textContent = 'Verificando…';
  try {
    const { sv_wrapped } = await storage.get('sv_wrapped');
    const mnemonic = await C.unwrapSeedWithPassword(sv_wrapped, $('l-pw').value);
    await openSession(mnemonic);
  } catch (e) {
    err('l-err', 'Contrasena incorrecta.');
  }
  $('l-go').textContent = 'Desbloquear';
});
$('l-pw').addEventListener('keydown', e => { if (e.key === 'Enter') $('l-go').click(); });
$('l-reset').addEventListener('click', async () => {
  if (!confirm('Se borrara la configuracion de este navegador (la boveda del servidor no se toca). Continuar?')) return;
  await storage.clear(); await storage.sClear();
  view('v-setup');
});

// ---------- acciones ----------
$('m-sync').addEventListener('click', async () => {
  await pull(session.keys);
  session.vault = await loadVault(session.keys);
  await renderMain();
});
$('m-lock').addEventListener('click', lock);

// ---------- arranque ----------
(async () => {
  const { sv_wrapped } = await storage.get('sv_wrapped');
  if (!sv_wrapped) { view('v-setup'); return; }
  const { sv_session } = await storage.sGet('sv_session');
  if (sv_session && (Date.now() - sv_session.unlockedAt) < LOCK_MS) {
    await openSession(sv_session.mnemonic); // renueva el temporizador
  } else {
    await storage.sClear();
    view('v-lock');
  }
})();
})();
