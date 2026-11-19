// Prueba de sincronizacion: reinstalacion del servidor vs eliminacion intencional.
// Reproduce la logica de openSession/pushVault de app.js frente a las respuestas
// 404 (boveda inexistente) y 410 (boveda retirada con lapida).
// Requiere el servidor corriendo:  node desarrollo/tests/test-retiro.js
const C = require('../shared/crypto.js');
const https = require('https');
const fs = require('fs');
const path = require('path');

const BASE = 'https://localhost:' + (process.env.SV_PORT || 8443);
const DATA_DIR = path.join(__dirname, '..', '..', 'bovedas');
const agent = new https.Agent({ rejectUnauthorized: false });

function req(method, p, body, token) {
  return new Promise((resolve, reject) => {
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers['X-Auth-Token'] = token;
    const r = https.request(BASE + p, { method, agent, headers }, res => {
      let out = ''; res.on('data', c => out += c);
      res.on('end', () => resolve({ status: res.statusCode, data: JSON.parse(out || '{}') }));
    });
    r.on('error', reject);
    if (body) r.write(JSON.stringify(body));
    r.end();
  });
}

let passed = 0, failed = 0;
const assert = (c, n) => { c ? (passed++, console.log('  OK  ' + n)) : (failed++, console.log('  FALLO ' + n)); };
const fingerprint = keys => { const h = keys.vaultId.slice(0, 8).toUpperCase(); return h.slice(0, 4) + '-' + h.slice(4); };

// Dispositivo simulado: misma logica que openSession() de app.js
async function deviceOpen(dev) {
  const r = await req('GET', '/api/vault/' + dev.keys.vaultId);
  if (r.status === 410) { dev.localStorage = { sv_wrapped: null, sv_cache: null }; return 'retirada'; }
  if (r.status === 404) {
    if (dev.vault.entries.length > 0) {
      const p = await C.encryptVault(dev.vault, dev.keys);
      const put = await req('PUT', '/api/vault/' + dev.keys.vaultId, p, dev.keys.authToken);
      if (put.status === 410) { dev.localStorage = { sv_wrapped: null, sv_cache: null }; return 'retirada'; }
      return put.status === 200 ? 'restaurada' : 'error ' + put.status;
    }
    return 'vacia';
  }
  return r.status === 200 ? 'sincronizada' : 'error ' + r.status;
}

(async () => {
  console.log('\n=== Escenario 1: reinstalacion del servidor (sin lapida) ===');
  const m1 = await C.generateMnemonic();
  const k1 = await C.deriveKeys(await C.mnemonicToSeed(m1));
  const vault = { entries: [{ id: 'g1', name: 'Correo de la tienda', username: 'tienda', password: 'Clave#2026', url: 'https://mail.google.com', notes: '' }] };
  const payload = await C.encryptVault(vault, k1);
  const put1 = await req('PUT', '/api/vault/' + k1.vaultId, payload, k1.authToken);
  assert(put1.status === 200, 'Gladys crea la boveda en el servidor (200)');
  const respaldo = { format: 'svault', v: 1, vaultId: k1.vaultId, payload }; // .svault exportado antes del retiro

  fs.unlinkSync(path.join(DATA_DIR, k1.vaultId + '.json')); // reinstalacion: la carpeta bovedas queda sin el archivo
  const g404 = await req('GET', '/api/vault/' + k1.vaultId);
  assert(g404.status === 404, 'tras la reinstalacion el servidor responde 404 (no existe, sin lapida)');
  const devA = { keys: k1, vault: await C.decryptVault(payload, k1), localStorage: { sv_wrapped: 'x', sv_cache: payload } };
  assert(await deviceOpen(devA) === 'restaurada', 'el dispositivo con copia local la vuelve a subir (restauracion esperada)');
  const g200 = await req('GET', '/api/vault/' + k1.vaultId);
  const back = await C.decryptVault(g200.data.payload, k1);
  assert(g200.status === 200 && back.entries[0].id === 'g1', 'otro dispositivo descarga la boveda restaurada con sus credenciales');

  console.log('\n=== Escenario 2: eliminacion intencional (retiro con lapida) ===');
  const del = await req('DELETE', '/api/vault/' + k1.vaultId, null, k1.authToken);
  assert(del.status === 200 && typeof del.data.deletedAt === 'number', 'Gladys elimina la boveda anterior (200 con fecha de retiro)');
  assert(!fs.existsSync(path.join(DATA_DIR, k1.vaultId + '.json')), 'el archivo cifrado de la boveda ya no existe');
  const tomb = JSON.parse(fs.readFileSync(path.join(DATA_DIR, k1.vaultId + '.deleted.json'), 'utf8'));
  assert(tomb.deletedAt === del.data.deletedAt && Object.keys(tomb).sort().join() === 'authHash,deletedAt', 'queda una lapida solo con el hash del token y la fecha (sin datos cifrados)');
  const g410 = await req('GET', '/api/vault/' + k1.vaultId);
  assert(g410.status === 410, 'la lectura de la boveda retirada responde 410 (no 404)');
  const devB = { keys: k1, vault: await C.decryptVault(payload, k1), localStorage: { sv_wrapped: 'x', sv_cache: payload } };
  assert(await deviceOpen(devB) === 'retirada', 'un dispositivo desactualizado con copia local NO la vuelve a subir');
  assert(devB.localStorage.sv_cache === null && devB.localStorage.sv_wrapped === null, 'ese dispositivo borra su copia cifrada y su contrasena local');
  const putStale = await req('PUT', '/api/vault/' + k1.vaultId, payload, k1.authToken);
  assert(putStale.status === 410, 'un PUT con el token correcto de la seed antigua tambien es rechazado (410)');
  assert(!fs.existsSync(path.join(DATA_DIR, k1.vaultId + '.json')), 'la boveda retirada no reaparece en el servidor');
  const del2 = await req('DELETE', '/api/vault/' + k1.vaultId, null, k1.authToken);
  assert(del2.status === 410, 'eliminar de nuevo una boveda retirada responde 410');

  console.log('\n=== Escenario 3: rotacion de la seed y verificacion ===');
  const m2 = await C.generateMnemonic();
  const k2 = await C.deriveKeys(await C.mnemonicToSeed(m2));
  const put2 = await req('PUT', '/api/vault/' + k2.vaultId, await C.encryptVault(vault, k2), k2.authToken);
  assert(put2.status === 200, 'la nueva boveda (seed nueva) se crea normalmente');
  assert((await req('GET', '/api/vault/' + k1.vaultId)).status === 410 && (await req('GET', '/api/vault/' + k2.vaultId)).status === 200, 'en el servidor la boveda vieja queda retirada y la nueva vigente');
  const k2b = await C.deriveKeys(await C.mnemonicToSeed(m2)); // segundo dispositivo autorizado
  assert(fingerprint(k2) === fingerprint(k2b), 'dos dispositivos con la seed nueva muestran la misma huella (' + fingerprint(k2) + ')');
  assert(fingerprint(k1) !== fingerprint(k2), 'la huella de la boveda vieja (' + fingerprint(k1) + ') es distinta de la nueva');

  console.log('\n=== Alcance frente a copias previas ===');
  const viejo = await C.decryptVault(respaldo.payload, k1);
  assert(viejo.entries[0].password === 'Clave#2026', 'un respaldo .svault exportado antes del retiro sigue legible con la seed antigua (limite documentado)');

  await req('DELETE', '/api/vault/' + k2.vaultId, null, k2.authToken);
  console.log('\nResultado: ' + passed + ' OK, ' + failed + ' fallos');
  process.exit(failed ? 1 : 0);
})().catch(e => { console.error(e); process.exit(1); });
