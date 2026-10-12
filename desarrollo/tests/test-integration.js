// Prueba de integracion: simula el flujo wallet completo.
// Dispositivo A crea la boveda y la sube; Dispositivo B, solo con la seed,
// deriva las mismas claves, descarga el blob y lo descifra.
// Ejecutar con el servidor corriendo: node tests/test-integration.js
const C = require('../shared/crypto.js');
const https = require('https');

const BASE = 'https://localhost:8443';
const agent = new https.Agent({ rejectUnauthorized: false }); // cert autofirmado local

function req(method, path, body, headers = {}) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const r = https.request(BASE + path, { method, agent, headers: { 'Content-Type': 'application/json', ...headers } }, res => {
      let out = '';
      res.on('data', c => out += c);
      res.on('end', () => resolve({ status: res.statusCode, body: JSON.parse(out || '{}') }));
    });
    r.on('error', reject);
    if (data) r.write(data);
    r.end();
  });
}


// --- Regresion: servidor reinstalado, el dispositivo restaura su boveda ---
// (reproduce la logica de openSession en app.js tras el fix)
async function scenarioReinstall(C, req, assert) {
  const m = await C.generateMnemonic();
  const keys = await C.deriveKeys(await C.mnemonicToSeed(m));
  const vault = { entries: [{ id: 'r1', name: 'Portal', username: 'u', password: 'p', url: '', notes: '' }] };
  const cachePayload = await C.encryptVault(vault, keys);
  // el dispositivo tiene cache local, el servidor NO tiene la boveda (recien reinstalado)
  const g1 = await req('GET', '/api/vault/' + keys.vaultId);
  assert(g1.status === 404, 'servidor reinstalado: la boveda no existe (404)');
  // logica de la app: 404 + entradas locales => pushVault
  let session = { vault: await C.decryptVault(cachePayload, keys), keys };
  if (g1.status === 404 && session.vault.entries.length > 0) {
    const p = await C.encryptVault(session.vault, keys);
    const put = await req('PUT', '/api/vault/' + keys.vaultId, p, { 'X-Auth-Token': keys.authToken });
    assert(put.status === 200, 'el dispositivo restaura la boveda automaticamente');
  }
  const g2 = await req('GET', '/api/vault/' + keys.vaultId);
  const back = await C.decryptVault(g2.body.payload, keys);
  assert(back.entries[0].id === 'r1', 'otro dispositivo ya puede descargar la boveda restaurada');
  await req('DELETE', '/api/vault/' + keys.vaultId, null, { 'X-Auth-Token': keys.authToken });
}

let passed = 0, failed = 0;
function assert(cond, name) {
  if (cond) { passed++; console.log('  OK  ' + name); }
  else { failed++; console.log('  FALLO ' + name); }
}

(async () => {
  console.log('\n=== DISPOSITIVO A: crear boveda y subirla ===');
  const mnemonic = await C.generateMnemonic();
  console.log('  seed generada: "' + mnemonic.split(' ').slice(0, 3).join(' ') + ' …" (24 palabras)');

  const seedA = await C.mnemonicToSeed(mnemonic);
  const keysA = await C.deriveKeys(seedA);

  const vault = {
    entries: [
      { id: 'e1', name: 'Sistema de facturacion', username: 'admin@novedadesgladys.co', password: 'Factura#2026!', url: 'https://facturacion.ejemplo.com', notes: 'cuenta principal' },
      { id: 'e2', name: 'Portal proveedor textil', username: 'compras.gladys', password: 'Textil$8821', url: 'https://proveedor-textil.com', notes: '' }
    ]
  };

  const payload = await C.encryptVault(vault, keysA);
  const put = await req('PUT', '/api/vault/' + keysA.vaultId, payload, { 'X-Auth-Token': keysA.authToken });
  assert(put.status === 200 && put.body.saved, 'A sube la boveda cifrada (PUT 200)');

  console.log('\n=== SERVIDOR: verificar que es ciego ===');
  const fs = require('fs');
  const path = require('path');
  const candidates = [
    path.join(__dirname, '../../bovedas'),   // layout portable
    path.join(__dirname, '../server/data')   // layout de desarrollo
  ];
  const dataDir = candidates.find(d => fs.existsSync(path.join(d, keysA.vaultId + '.json')));
  const raw = fs.readFileSync(path.join(dataDir, keysA.vaultId + '.json'), 'utf8');
  assert(!raw.includes('Factura#2026'), 'archivo en disco NO contiene contrasenas en claro');
  assert(!raw.includes('admin@novedadesgladys'), 'archivo en disco NO contiene usuarios en claro');
  assert(!raw.includes(mnemonic.split(' ')[0]), 'archivo en disco NO contiene la seed');
  assert(!raw.includes(keysA.authToken), 'servidor guarda hash del token, no el token');

  console.log('\n=== DISPOSITIVO B: abrir con la seed (como wallet) ===');
  // B solo tiene las 24 palabras. Nada mas.
  const seedB = await C.mnemonicToSeed(mnemonic);
  const keysB = await C.deriveKeys(seedB);
  assert(keysB.vaultId === keysA.vaultId, 'B deriva el mismo vaultId sin comunicarse con A');

  const get = await req('GET', '/api/vault/' + keysB.vaultId);
  assert(get.status === 200, 'B descarga el blob cifrado (GET 200)');

  const opened = await C.decryptVault(get.body.payload, keysB);
  assert(opened.entries.length === 2, 'B descifra la boveda completa');
  assert(opened.entries[0].password === 'Factura#2026!', 'B recupera las contrasenas exactas');

  console.log('\n=== SEGURIDAD: ataques rechazados ===');
  const attacker = await C.deriveKeys(await C.mnemonicToSeed(await C.generateMnemonic()));

  const overwrite = await req('PUT', '/api/vault/' + keysA.vaultId, payload, { 'X-Auth-Token': attacker.authToken });
  assert(overwrite.status === 403, 'atacante con token equivocado no puede sobrescribir (403)');

  const del = await req('DELETE', '/api/vault/' + keysA.vaultId, null, { 'X-Auth-Token': attacker.authToken });
  assert(del.status === 403, 'atacante no puede eliminar la boveda (403)');

  const plaintextAttempt = await req('PUT', '/api/vault/' + keysA.vaultId,
    { user: 'gladys', password: 'texto-plano' }, { 'X-Auth-Token': keysA.authToken });
  assert(plaintextAttempt.status === 422, 'servidor rechaza cualquier payload que no sea blob cifrado (422)');

  const badId = await req('GET', '/api/vault/no-es-hex');
  assert(badId.status === 400, 'vaultId con formato invalido es rechazado (400)');

  console.log('\n=== SINCRONIZACION: B actualiza, A recibe el cambio ===');
  opened.entries.push({ id: 'e3', name: 'Correo corporativo', username: 'gerencia@novedadesgladys.co', password: 'Nuevo*334', url: 'https://mail.ejemplo.com', notes: 'agregada desde dispositivo B' });
  const payload2 = await C.encryptVault(opened, keysB);
  const put2 = await req('PUT', '/api/vault/' + keysB.vaultId, payload2, { 'X-Auth-Token': keysB.authToken });
  assert(put2.status === 200, 'B sube la version actualizada');

  const stale = await req('PUT', '/api/vault/' + keysA.vaultId, payload, { 'X-Auth-Token': keysA.authToken });
  assert(stale.status === 409, 'version antigua es rechazada (proteccion anti-retroceso, 409)');

  const getA = await req('GET', '/api/vault/' + keysA.vaultId);
  const syncedA = await C.decryptVault(getA.body.payload, keysA);
  assert(syncedA.entries.length === 3, 'A descarga y ve la entrada creada por B');

  console.log('\n=== REGRESION: servidor reinstalado ===');
  await scenarioReinstall(C, req, assert);

  console.log('\n=== ELIMINACION SEGURA ===');
  const delOk = await req('DELETE', '/api/vault/' + keysA.vaultId, null, { 'X-Auth-Token': keysA.authToken });
  assert(delOk.status === 200 && delOk.body.deleted, 'dueno de la seed elimina la boveda (200)');
  const gone = await req('GET', '/api/vault/' + keysA.vaultId);
  assert(gone.status === 404, 'la boveda ya no existe (404)');

  console.log('\nResultado: ' + passed + ' pruebas OK, ' + failed + ' fallos\n');
  process.exit(failed ? 1 : 0);
})().catch(e => { console.error('ERROR FATAL:', e); process.exit(1); });
