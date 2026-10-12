// Simula el entorno de un NAVEGADOR: carga wordlist.js y crypto.js como
// <script> clasicos en un contexto SIN require ni module, exactamente como
// los ejecuta Chrome. Detecta errores que solo aparecen en el navegador.
// Ejecutar: node tests/test-browser-env.js
const vm = require('vm');
const fs = require('fs');
const path = require('path');

let passed = 0, failed = 0;
const assert = (c, n) => { c ? (passed++, console.log('  OK  ' + n)) : (failed++, console.log('  FALLO ' + n)); };

(async () => {
  for (const dir of ['../../app/pwa', '../../extension']) {
    const base = path.join(__dirname, dir);
    console.log('\n[Entorno navegador] ' + dir);

    // contexto tipo navegador: sin require, sin module, con crypto y TextEncoder
    const sandbox = {
      crypto: globalThis.crypto,
      TextEncoder, TextDecoder,
      btoa: s => Buffer.from(s, 'binary').toString('base64'),
      atob: s => Buffer.from(s, 'base64').toString('binary'),
      console
    };
    sandbox.globalThis = sandbox;
    sandbox.self = sandbox;
    sandbox.window = sandbox;
    const ctx = vm.createContext(sandbox);

    // cargar los scripts en el mismo orden que el HTML
    vm.runInContext(fs.readFileSync(path.join(base, 'wordlist.js'), 'utf8'), ctx, { filename: 'wordlist.js' });
    assert(Array.isArray(sandbox.BIP39_WORDLIST) && sandbox.BIP39_WORDLIST.length === 2048,
      'wordlist queda expuesta en el ambito global del navegador');

    let loadError = null;
    try {
      vm.runInContext(fs.readFileSync(path.join(base, 'crypto.js'), 'utf8'), ctx, { filename: 'crypto.js' });
    } catch (e) { loadError = e; }
    assert(!loadError, 'crypto.js carga sin errores' + (loadError ? ' -> ' + loadError.message : ''));
    assert(sandbox.SecureVaultCrypto && typeof sandbox.SecureVaultCrypto.generateMnemonic === 'function',
      'SecureVaultCrypto queda disponible para app.js');

    // flujo real del boton "Crear boveda nueva"
    const C = sandbox.SecureVaultCrypto;
    const m = await C.generateMnemonic();
    assert(m.split(' ').length === 24, 'generateMnemonic produce 24 palabras en el navegador');
    const keys = await C.deriveKeys(await C.mnemonicToSeed(m));
    const payload = await C.encryptVault({ entries: [{ id: '1', password: 'x' }] }, keys);
    const back = await C.decryptVault(payload, keys);
    assert(back.entries[0].password === 'x', 'cifrado y descifrado completos en entorno navegador');
  }

  console.log('\nResultado: ' + passed + ' OK, ' + failed + ' fallos\n');
  process.exit(failed ? 1 : 0);
})().catch(e => { console.error('ERROR FATAL:', e); process.exit(1); });
