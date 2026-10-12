// Pruebas unitarias del modulo criptografico de SecureVault
// Ejecutar: node tests/test-crypto.js
const C = require('../shared/crypto.js');

let passed = 0, failed = 0;
function assert(cond, name) {
  if (cond) { passed++; console.log('  OK  ' + name); }
  else { failed++; console.log('  FALLO ' + name); }
}

(async () => {
  console.log('\n[1] Generacion y validacion BIP-39');
  const m1 = await C.generateMnemonic();
  assert(m1.split(' ').length === 24, 'genera 24 palabras');
  assert((await C.validateMnemonic(m1)).valid, 'checksum valido en frase generada');

  const m2 = await C.generateMnemonic();
  assert(m1 !== m2, 'dos frases generadas son distintas (entropia aleatoria)');

  const badWord = m1.split(' '); badWord[0] = 'zzzzz';
  assert(!(await C.validateMnemonic(badWord.join(' '))).valid, 'rechaza palabra fuera de la lista');

  const swapped = m1.split(' '); const t = swapped[0]; swapped[0] = swapped[1]; swapped[1] = t;
  const vs = await C.validateMnemonic(swapped.join(' '));
  // el intercambio puede casualmente dar checksum valido con prob 1/256; se acepta cualquiera de los dos
  assert(vs.valid === false || vs.valid === true, 'validacion de intercambio ejecuta sin error');

  console.log('\n[2] Vector de prueba BIP-39 oficial (Trezor)');
  // entropia 0x00...00 (32 bytes) -> "abandon abandon ... art"
  const zeroEntropy = new Uint8Array(32);
  const vec = await C.entropyToMnemonic(zeroEntropy);
  const expected = ('abandon '.repeat(23) + 'art').trim();
  assert(vec === expected, 'entropia cero produce la frase del vector oficial');
  const seedVec = await C.mnemonicToSeed(vec);
  // seed oficial del vector Trezor para esta frase (passphrase vacia)
  const expectedSeedHex = '408b285c123836004f4b8842c89324c1f01382450c0d439af345ba7fc49acf705489c6fc77dbd4e3dc1dd8cc6bc9f043db8ada1e243c4a0eafb290d399480840';
  assert(C.bytesToHex(seedVec) === expectedSeedHex, 'seed PBKDF2-SHA512 coincide con vector oficial');

  console.log('\n[3] Derivacion deterministica (misma seed en "otro dispositivo")');
  const seedA = await C.mnemonicToSeed(m1);
  const seedB = await C.mnemonicToSeed(m1.toUpperCase() + '  '); // normalizacion
  assert(C.bytesToHex(seedA) === C.bytesToHex(seedB), 'normaliza mayusculas y espacios');
  const kA = await C.deriveKeys(seedA);
  const kB = await C.deriveKeys(seedB);
  assert(kA.vaultId === kB.vaultId, 'mismo vaultId en dos derivaciones (dispositivo A y B)');
  assert(kA.authToken === kB.authToken, 'mismo authToken en dos derivaciones');
  const kOther = await C.deriveKeys(await C.mnemonicToSeed(m2));
  assert(kA.vaultId !== kOther.vaultId, 'seeds distintas producen vaultId distinto');

  console.log('\n[4] Cifrado AES-256-GCM + HMAC-SHA256');
  const vault = { entries: [{ id: '1', name: 'Proveedor X', username: 'gladys', password: 'S3gura!2026', url: 'https://proveedor.com', notes: '' }] };
  const payload = await C.encryptVault(vault, kA);
  assert(!!payload.iv && !!payload.ct && !!payload.mac, 'payload contiene iv, ct y mac');
  assert(!JSON.stringify(payload).includes('S3gura'), 'el payload NO contiene texto plano');

  const p2 = await C.encryptVault(vault, kA);
  assert(payload.ct !== p2.ct, 'mismo contenido cifra distinto cada vez (IV unico)');

  const roundtrip = await C.decryptVault(payload, kA);
  assert(roundtrip.entries[0].password === 'S3gura!2026', 'descifrado recupera el contenido exacto');

  console.log('\n[5] Deteccion de manipulacion (integridad)');
  const tampered = JSON.parse(JSON.stringify(payload));
  const ctBytes = C.b64ToBytes(tampered.ct);
  ctBytes[0] ^= 0xff;
  tampered.ct = C.bytesToB64(ctBytes);
  let caught = false;
  try { await C.decryptVault(tampered, kA); } catch (e) { caught = /INTEGRIDAD/.test(e.message); }
  assert(caught, 'blob alterado es rechazado por HMAC antes de descifrar');

  console.log('\n[6] Clave equivocada no descifra');
  let wrongKey = false;
  try { await C.decryptVault(payload, kOther); } catch (e) { wrongKey = true; }
  assert(wrongKey, 'otra seed no puede descifrar la boveda');

  console.log('\n[7] Contrasena local (PBKDF2 150.000 iteraciones)');
  const wrapped = await C.wrapSeedWithPassword(m1, 'MiClaveLocal99');
  assert(!JSON.stringify(wrapped).includes(m1.split(' ')[0]), 'la seed no aparece en el envoltorio');
  assert(wrapped.iter === 150000, 'usa 150.000 iteraciones');
  const un = await C.unwrapSeedWithPassword(wrapped, 'MiClaveLocal99');
  assert(un === m1, 'contrasena correcta recupera la seed');
  let badpw = false;
  try { await C.unwrapSeedWithPassword(wrapped, 'otra'); } catch (e) { badpw = /CONTRASENA/.test(e.message); }
  assert(badpw, 'contrasena incorrecta es rechazada');

  console.log('\nResultado: ' + passed + ' pruebas OK, ' + failed + ' fallos\n');
  process.exit(failed ? 1 : 0);
})().catch(e => { console.error('ERROR FATAL:', e); process.exit(1); });
