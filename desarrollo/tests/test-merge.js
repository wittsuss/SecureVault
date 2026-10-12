// Pruebas de FUSION multi-dispositivo.
// Incluye el escenario reportado: el servidor pierde su carpeta "bovedas",
// un celular con 1 credencial sube primero, y el PC (que tenia varias) entra
// despues. Nada debe perderse. Requiere el servidor corriendo.
const C = require('../shared/crypto.js');
const https = require('https');
const agent = new https.Agent({ rejectUnauthorized: false });

function req(method, path, body, token) {
  return new Promise((resolve, reject) => {
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers['X-Auth-Token'] = token;
    const r = https.request('https://localhost:8443' + path, { method, agent, headers }, res => {
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

// reproduce la logica de openSession de app.js
async function openLikeApp(localVault, keys) {
  let vault = C.normalizeVault(localVault);
  const r = await req('GET', '/api/vault/' + keys.vaultId);
  if (r.status === 200) {
    const remote = C.normalizeVault(await C.decryptVault(r.data.payload, keys));
    const merged = C.mergeVaults(vault, remote);
    vault = merged;
    if (C.vaultSignature(merged) !== C.vaultSignature(remote)) {
      const p = await C.encryptVault(vault, keys);
      await req('PUT', '/api/vault/' + keys.vaultId, p, keys.authToken);
    }
  } else if (r.status === 404 && vault.entries.length > 0) {
    const p = await C.encryptVault(vault, keys);
    await req('PUT', '/api/vault/' + keys.vaultId, p, keys.authToken);
  }
  return vault;
}

(async () => {
  const now = Date.now();

  console.log('\n[Unidad] mergeVaults');
  const A = { entries: [{ id: '1', name: 'uno', updatedAt: now - 100 }, { id: '2', name: 'dos', updatedAt: now - 100 }], deleted: {} };
  const B = { entries: [{ id: '3', name: 'tres', updatedAt: now - 50 }], deleted: {} };
  const u = C.mergeVaults(A, B);
  assert(u.entries.length === 3, 'union: 2 + 1 credenciales = 3, nada se pierde');

  const A2 = { entries: [{ id: '1', name: 'viejo', updatedAt: now - 100 }], deleted: {} };
  const B2 = { entries: [{ id: '1', name: 'editado', updatedAt: now - 10 }], deleted: {} };
  assert(C.mergeVaults(A2, B2).entries[0].name === 'editado', 'conflicto: gana la edicion mas reciente de ESA credencial');

  const conTumba = C.mergeVaults(
    { entries: [{ id: '9', name: 'x', updatedAt: now - 100 }], deleted: {} },
    { entries: [], deleted: { '9': now - 10 } });
  assert(conTumba.entries.length === 0, 'lapida: lo eliminado en un dispositivo no resucita al fusionar');

  const editTrasBorrar = C.mergeVaults(
    { entries: [{ id: '9', name: 'reeditado', updatedAt: now - 5 }], deleted: {} },
    { entries: [], deleted: { '9': now - 10 } });
  assert(editTrasBorrar.entries.length === 1, 'si editaste DESPUES del borrado ajeno, la edicion gana');

  assert(C.vaultSignature(A) === C.vaultSignature({ entries: [...A.entries].reverse(), deleted: {} }),
    'la firma no depende del orden de las credenciales');

  console.log('\n[Escenario reportado] carpeta bovedas eliminada + celular sube primero');
  const seed = await C.mnemonicToSeed(await C.generateMnemonic());
  const keys = await C.deriveKeys(seed);

  // 1) el PC tenia 2 credenciales y las habia subido
  const pcVault = { entries: [
    { id: 'pc1', name: 'Facturacion', username: 'a', password: 'p1', url: '', notes: '', updatedAt: now - 5000 },
    { id: 'pc2', name: 'Proveedor', username: 'b', password: 'p2', url: '', notes: '', updatedAt: now - 5000 }
  ], deleted: {} };
  await req('PUT', '/api/vault/' + keys.vaultId, await C.encryptVault(pcVault, keys), keys.authToken);

  // 2) se elimina la carpeta bovedas (el servidor pierde todo)
  await req('DELETE', '/api/vault/' + keys.vaultId, null, keys.authToken);
  assert((await req('GET', '/api/vault/' + keys.vaultId)).status === 404, 'servidor vacio (carpeta eliminada)');

  // 3) el CELULAR (tiene 1 credencial propia en su cache) entra primero
  const celCache = { entries: [{ id: 'cel1', name: 'Instagram', username: 'c', password: 'p3', url: '', notes: '', updatedAt: now - 1000 }], deleted: {} };
  const celVault = await openLikeApp(celCache, keys);
  assert(celVault.entries.length === 1, 'el celular restaura su unica credencial al servidor');

  // 4) el PC entra despues con su cache de 2 credenciales
  const pcResult = await openLikeApp(pcVault, keys);
  assert(pcResult.entries.length === 3, 'FUSION: el PC ve las 3 credenciales (2 suyas + 1 del celular), NADA se pierde');

  // 5) el celular sincroniza de nuevo y tambien ve las 3
  const celResult = await openLikeApp(celVault, keys);
  assert(celResult.entries.length === 3, 'el celular tambien termina con las 3 credenciales');

  console.log('\n[Eliminacion intencional] se propaga sin resucitar');
  // el PC elimina pc1 con lapida y sube
  pcResult.deleted['pc1'] = Date.now();
  pcResult.entries = pcResult.entries.filter(e => e.id !== 'pc1');
  await req('PUT', '/api/vault/' + keys.vaultId, await C.encryptVault(pcResult, keys), keys.authToken);
  // el celular (cache con 3) sincroniza: debe quedar con 2, sin resucitar pc1
  const celFinal = await openLikeApp(celResult, keys);
  assert(celFinal.entries.length === 2 && !celFinal.entries.find(e => e.id === 'pc1'),
    'la credencial eliminada en el PC desaparece del celular y NO resucita');

  await req('DELETE', '/api/vault/' + keys.vaultId, null, keys.authToken);
  console.log('\nResultado: ' + passed + ' OK, ' + failed + ' fallos\n');
  process.exit(failed ? 1 : 0);
})().catch(e => { console.error('ERROR FATAL:', e); process.exit(1); });
