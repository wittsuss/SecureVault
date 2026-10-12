/*
 * SecureVault - Modulo criptografico compartido
 * Toda la criptografia ocurre en el cliente (Zero-Knowledge).
 * Funciona en navegador (window.crypto) y en Node 20+ (globalThis.crypto).
 *
 * Flujo de derivacion (deterministico, igual que una wallet):
 *   24 palabras BIP-39
 *     -> PBKDF2-HMAC-SHA512 (salt "mnemonic", 2048 iter)  [estandar BIP-39]
 *     -> seed de 64 bytes
 *     -> HMAC-SHA256(seed, proposito) para cada clave:
 *          encKey   (AES-256-GCM)   cifra la boveda
 *          macKey   (HMAC-SHA256)   firma de integridad
 *          vaultId  (hex)           identificador publico en el servidor
 *          authToken(b64)           prueba de escritura ante el servidor
 *
 * El servidor solo conoce vaultId y el hash del authToken.
 * Nunca ve la seed, las claves ni ningun dato en texto plano.
 */

(function (root) {
  'use strict';

  const subtle = (root.crypto && root.crypto.subtle) || null;
  if (!subtle) {
    // Safari/iOS solo expone crypto.subtle en contextos seguros (HTTPS con certificado aceptado)
    root.SecureVaultCryptoError = 'Este navegador no expone la Web Crypto API. ' +
      'Verifica que la direccion empiece por https:// y que aceptaste el certificado. ' +
      'Si el problema continua, usa Chrome.';
    return;
  }

  const WORDLIST = root.BIP39_WORDLIST
    || (typeof BIP39_WORDLIST !== 'undefined' ? BIP39_WORDLIST : null)
    || (typeof require !== 'undefined' ? require('./wordlist.js') : null);
  if (!WORDLIST || WORDLIST.length !== 2048) {
    root.SecureVaultCryptoError = 'La lista de palabras BIP-39 no cargo. Recarga la pagina (desliza hacia abajo).';
    return;
  }

  const enc = new TextEncoder();
  const dec = new TextDecoder();

  // ---------- utilidades de bytes ----------
  function bytesToHex(b) {
    return Array.from(new Uint8Array(b)).map(x => x.toString(16).padStart(2, '0')).join('');
  }
  function hexToBytes(h) {
    const out = new Uint8Array(h.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
    return out;
  }
  function bytesToB64(b) {
    const u = new Uint8Array(b);
    let s = '';
    for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
    return (root.btoa ? root.btoa(s) : Buffer.from(u).toString('base64'));
  }
  function b64ToBytes(s) {
    if (root.atob) {
      const bin = root.atob(s);
      const out = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    }
    return new Uint8Array(Buffer.from(s, 'base64'));
  }
  function randomBytes(n) {
    const b = new Uint8Array(n);
    root.crypto.getRandomValues(b);
    return b;
  }
  function constantTimeEqual(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  }

  // ---------- BIP-39 ----------
  async function sha256(bytes) {
    return new Uint8Array(await subtle.digest('SHA-256', bytes));
  }

  // 32 bytes de entropia -> 24 palabras (con checksum de 8 bits)
  async function generateMnemonic() {
    const entropy = randomBytes(32);
    return entropyToMnemonic(entropy);
  }

  async function entropyToMnemonic(entropy) {
    if (entropy.length !== 32) throw new Error('Se requieren 32 bytes de entropia');
    const hash = await sha256(entropy);
    const checksumBits = 8; // 256/32
    let bits = '';
    for (const byte of entropy) bits += byte.toString(2).padStart(8, '0');
    bits += hash[0].toString(2).padStart(8, '0').slice(0, checksumBits);
    const words = [];
    for (let i = 0; i < 24; i++) {
      const idx = parseInt(bits.slice(i * 11, (i + 1) * 11), 2);
      words.push(WORDLIST[idx]);
    }
    return words.join(' ');
  }

  async function validateMnemonic(mnemonic) {
    const words = mnemonic.trim().toLowerCase().split(/\s+/);
    if (words.length !== 24) return { valid: false, reason: 'Deben ser exactamente 24 palabras' };
    let bits = '';
    for (const w of words) {
      const idx = WORDLIST.indexOf(w);
      if (idx === -1) return { valid: false, reason: 'Palabra no valida: "' + w + '"' };
      bits += idx.toString(2).padStart(11, '0');
    }
    const entropyBits = bits.slice(0, 256);
    const checksum = bits.slice(256);
    const entropy = new Uint8Array(32);
    for (let i = 0; i < 32; i++) entropy[i] = parseInt(entropyBits.slice(i * 8, (i + 1) * 8), 2);
    const hash = await sha256(entropy);
    const expected = hash[0].toString(2).padStart(8, '0');
    if (checksum !== expected) return { valid: false, reason: 'Checksum invalido: la frase tiene un error' };
    return { valid: true };
  }

  // mnemonic -> seed de 64 bytes (PBKDF2-HMAC-SHA512, estandar BIP-39)
  async function mnemonicToSeed(mnemonic) {
    const normalized = mnemonic.trim().toLowerCase().split(/\s+/).join(' ');
    const keyMaterial = await subtle.importKey('raw', enc.encode(normalized), 'PBKDF2', false, ['deriveBits']);
    const bits = await subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-512', salt: enc.encode('mnemonic'), iterations: 2048 },
      keyMaterial, 512
    );
    return new Uint8Array(bits);
  }

  // ---------- derivacion de claves de dominio ----------
  async function hmacSha256Raw(keyBytes, message) {
    const key = await subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return new Uint8Array(await subtle.sign('HMAC', key, enc.encode(message)));
  }

  async function deriveKeys(seed) {
    const encRaw = await hmacSha256Raw(seed, 'securevault:enc:v1');
    const macRaw = await hmacSha256Raw(seed, 'securevault:mac:v1');
    const idRaw  = await hmacSha256Raw(seed, 'securevault:id:v1');
    const authRaw = await hmacSha256Raw(seed, 'securevault:auth:v1');

    const encKey = await subtle.importKey('raw', encRaw, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    const macKey = await subtle.importKey('raw', macRaw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);

    return {
      encKey,
      macKey,
      vaultId: bytesToHex(idRaw),      // identificador publico (no revela nada)
      authToken: bytesToB64(authRaw)   // prueba de escritura; el servidor guarda solo su hash
    };
  }

  // ---------- cifrado / descifrado de la boveda ----------
  // payload = { v, iv(b64), ct(b64), mac(b64), updatedAt }
  async function encryptVault(vaultObj, keys) {
    const iv = randomBytes(12);
    const plaintext = enc.encode(JSON.stringify(vaultObj));
    const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, keys.encKey, plaintext));
    // firma HMAC sobre iv || ct (integridad verificable antes de intentar descifrar)
    const signed = new Uint8Array(iv.length + ct.length);
    signed.set(iv, 0); signed.set(ct, iv.length);
    const mac = new Uint8Array(await subtle.sign('HMAC', keys.macKey, signed));
    return {
      v: 1,
      iv: bytesToB64(iv),
      ct: bytesToB64(ct),
      mac: bytesToB64(mac),
      updatedAt: Date.now()
    };
  }

  async function decryptVault(payload, keys) {
    const iv = b64ToBytes(payload.iv);
    const ct = b64ToBytes(payload.ct);
    const mac = b64ToBytes(payload.mac);
    const signed = new Uint8Array(iv.length + ct.length);
    signed.set(iv, 0); signed.set(ct, iv.length);
    const ok = await subtle.verify('HMAC', keys.macKey, mac, signed);
    if (!ok) throw new Error('INTEGRIDAD: la firma HMAC no coincide. La boveda fue alterada o esta corrupta.');
    const pt = await subtle.decrypt({ name: 'AES-GCM', iv }, keys.encKey, ct);
    return JSON.parse(dec.decode(pt));
  }

  // ---------- contrasena local (acceso rapido) ----------
  // Envuelve la seed con una clave derivada por PBKDF2-SHA256 (150.000 iter, NIST SP 800-132)
  const PBKDF2_ITERATIONS = 150000;

  async function passwordToKey(password, salt) {
    const material = await subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
    return subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: PBKDF2_ITERATIONS },
      material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
  }

  async function wrapSeedWithPassword(mnemonic, password) {
    const salt = randomBytes(16);
    const iv = randomBytes(12);
    const key = await passwordToKey(password, salt);
    const ct = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(mnemonic)));
    return { v: 1, kdf: 'PBKDF2-SHA256', iter: PBKDF2_ITERATIONS, salt: bytesToB64(salt), iv: bytesToB64(iv), ct: bytesToB64(ct) };
  }

  async function unwrapSeedWithPassword(wrapped, password) {
    const key = await passwordToKey(password, b64ToBytes(wrapped.salt));
    try {
      const pt = await subtle.decrypt({ name: 'AES-GCM', iv: b64ToBytes(wrapped.iv) }, key, b64ToBytes(wrapped.ct));
      return dec.decode(pt);
    } catch (e) {
      throw new Error('CONTRASENA: contrasena local incorrecta');
    }
  }


  // ---------- fusion de bovedas (sincronizacion multi-dispositivo) ----------
  // La boveda es { entries: [...], deleted: { id: timestampEliminacion } }.
  // "deleted" son lapidas: impiden que una credencial eliminada en un
  // dispositivo reaparezca al fusionar con otro que aun la tenia.

  function normalizeVault(v) {
    return {
      entries: (v && Array.isArray(v.entries)) ? v.entries : [],
      deleted: (v && v.deleted && typeof v.deleted === 'object') ? v.deleted : {}
    };
  }

  function mergeVaults(a, b) {
    a = normalizeVault(a); b = normalizeVault(b);
    // union de lapidas (se conserva la marca de tiempo mayor)
    const deleted = Object.assign({}, a.deleted);
    for (const id of Object.keys(b.deleted)) {
      deleted[id] = Math.max(b.deleted[id], deleted[id] || 0);
    }
    // union de credenciales por id; en conflicto gana la editada mas recientemente
    const byId = new Map();
    for (const e of a.entries.concat(b.entries)) {
      const cur = byId.get(e.id);
      if (!cur || (e.updatedAt || 0) > (cur.updatedAt || 0)) byId.set(e.id, e);
    }
    // una lapida elimina la credencial solo si es posterior a su ultima edicion
    // (si la editaste DESPUES de que otro dispositivo la borro, la edicion gana)
    const entries = [];
    for (const e of byId.values()) {
      if (deleted[e.id] && deleted[e.id] >= (e.updatedAt || 0)) continue;
      if (deleted[e.id]) delete deleted[e.id];
      entries.push(e);
    }
    // podar lapidas de mas de 90 dias para que la boveda no crezca sin limite
    const cutoff = Date.now() - 90 * 24 * 3600 * 1000;
    for (const id of Object.keys(deleted)) if (deleted[id] < cutoff) delete deleted[id];
    return { entries, deleted };
  }

  // firma comparable de una boveda: permite saber si dos estados son equivalentes
  function vaultSignature(v) {
    v = normalizeVault(v);
    const e = v.entries.map(x => x.id + ':' + (x.updatedAt || 0)).sort().join(',');
    const d = Object.keys(v.deleted).map(id => id + ':' + v.deleted[id]).sort().join(',');
    return e + '|' + d;
  }

  const api = {
    generateMnemonic, entropyToMnemonic, validateMnemonic, mnemonicToSeed,
    deriveKeys, encryptVault, decryptVault,
    wrapSeedWithPassword, unwrapSeedWithPassword,
    normalizeVault, mergeVaults, vaultSignature,
    bytesToHex, hexToBytes, bytesToB64, b64ToBytes, randomBytes, constantTimeEqual,
    PBKDF2_ITERATIONS
  };

  if (typeof module !== 'undefined') module.exports = api;
  root.SecureVaultCrypto = api;

})(typeof globalThis !== 'undefined' ? globalThis : this);
