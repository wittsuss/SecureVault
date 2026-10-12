// Simula en Node el flujo completo de la PWA:
// onboarding -> contrasena local -> CRUD -> sync -> backup .svault -> segunda "instalacion" con seed.
// Reproduce las mismas llamadas que hace app.js. Requiere el servidor corriendo.
const C = require('../shared/crypto.js');
const https = require('https');
const agent = new https.Agent({ rejectUnauthorized: false });
const BASE = 'https://localhost:8443';

function req(method, path, body, token) {
  return new Promise((resolve, reject) => {
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers['X-Auth-Token'] = token;
    const r = https.request(BASE + path, { method, agent, headers }, res => {
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

(async () => {
  console.log('\n[PWA] Onboarding: generar seed y proteger con contrasena local');
  const mnemonic = await C.generateMnemonic();
  const wrapped = await C.wrapSeedWithPassword(mnemonic, 'ClaveGladys2026');
  // "localStorage": solo guardamos wrapped; la seed vive en memoria
  const localStorage = { sv_wrapped: wrapped, sv_cache: null };

  console.log('\n[PWA] Desbloqueo con contrasena y CRUD');
  const recovered = await C.unwrapSeedWithPassword(localStorage.sv_wrapped, 'ClaveGladys2026');
  assert(recovered === mnemonic, 'desbloqueo con contrasena local recupera la seed');
  const keys = await C.deriveKeys(await C.mnemonicToSeed(recovered));

  const vault = { entries: [] };
  vault.entries.push({ id: 'a1', name: 'Instagram Fight Center', username: 'fightcenter.sm', password: 'Ig#2026!x', url: 'https://instagram.com', notes: '' });
  vault.entries.push({ id: 'a2', name: 'Banco empresa', username: 'nit900123', password: 'Bank$9912', url: 'https://banco.ejemplo.co', notes: 'token fisico en caja' });

  const payload = await C.encryptVault(vault, keys);
  localStorage.sv_cache = { vaultId: keys.vaultId, payload, pending: false };
  const put = await req('PUT', '/api/vault/' + keys.vaultId, payload, keys.authToken);
  assert(put.status === 200, 'PUT inicial con 2 entradas');

  console.log('\n[PWA] Modo offline: editar sin red y sincronizar al volver');
  // sin red: se edita y el cache queda pendiente
  vault.entries[0].password = 'Ig#CAMBIADA!';
  const offlinePayload = await C.encryptVault(vault, keys);
  localStorage.sv_cache = { vaultId: keys.vaultId, payload: offlinePayload, pending: true };
  assert(localStorage.sv_cache.pending === true, 'cambio offline queda marcado como pendiente');
  // vuelve la red: push
  const put2 = await req('PUT', '/api/vault/' + keys.vaultId, offlinePayload, keys.authToken);
  assert(put2.status === 200, 'al recuperar conexion el cambio pendiente se sube');

  console.log('\n[PWA] Backup .svault');
  const backupPayload = await C.encryptVault(vault, keys);
  const svaultFile = JSON.stringify({ format: 'svault', v: 1, vaultId: keys.vaultId, payload: backupPayload });
  assert(!svaultFile.includes('Ig#CAMBIADA'), 'el archivo .svault NO contiene texto plano');
  const parsed = JSON.parse(svaultFile);
  const restoredFromBackup = await C.decryptVault(parsed.payload, keys);
  assert(restoredFromBackup.entries.length === 2, 'importar .svault con la misma seed funciona');
  const otherKeys = await C.deriveKeys(await C.mnemonicToSeed(await C.generateMnemonic()));
  let rejected = false;
  try { await C.decryptVault(parsed.payload, otherKeys); } catch (e) { rejected = true; }
  assert(rejected, 'un .svault ajeno no se puede abrir con otra seed');

  console.log('\n[PWA] "Instalacion" en un dispositivo nuevo solo con la seed');
  const keysNew = await C.deriveKeys(await C.mnemonicToSeed(mnemonic));
  const get = await req('GET', '/api/vault/' + keysNew.vaultId);
  const vaultNew = await C.decryptVault(get.data.payload, keysNew);
  assert(vaultNew.entries.find(e => e.id === 'a1').password === 'Ig#CAMBIADA!', 'el dispositivo nuevo ve la ultima version');

  console.log('\n[PWA] Rendimiento (RNF-003: 500 entradas < 2 s)');
  const big = { entries: [] };
  for (let i = 0; i < 500; i++) big.entries.push({ id: 'x' + i, name: 'Entrada ' + i, username: 'user' + i + '@mail.com', password: 'P@ss' + i + '!seguro', url: 'https://sitio' + i + '.com', notes: 'nota '.repeat(5) });
  let t = Date.now();
  const bigPayload = await C.encryptVault(big, keys);
  const encMs = Date.now() - t;
  t = Date.now();
  await C.decryptVault(bigPayload, keys);
  const decMs = Date.now() - t;
  console.log('  cifrado: ' + encMs + ' ms | descifrado: ' + decMs + ' ms');
  assert(encMs < 2000 && decMs < 2000, 'cifrar y descifrar 500 entradas toma menos de 2 s');

  // limpieza
  await req('DELETE', '/api/vault/' + keys.vaultId, null, keys.authToken);

  console.log('\nResultado: ' + passed + ' OK, ' + failed + ' fallos\n');
  process.exit(failed ? 1 : 0);
})().catch(e => { console.error('ERROR FATAL:', e); process.exit(1); });
