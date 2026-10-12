/*
 * SecureVault - Servidor Zero-Knowledge
 * Node.js v20 LTS, sin dependencias externas (solo modulos nativos).
 *
 * El servidor es un "repositorio ciego":
 *   - Almacena blobs cifrados indexados por vaultId (derivado de la seed).
 *   - Nunca recibe texto plano, seeds ni claves.
 *   - Para escrituras exige un authToken (tambien derivado de la seed);
 *     el servidor guarda unicamente el SHA-256 del token, nunca el token.
 *
 * API:
 *   GET    /api/health              -> estado del servidor
 *   GET    /api/vault/:vaultId      -> blob cifrado (o 404)
 *   PUT    /api/vault/:vaultId      -> guarda blob (header X-Auth-Token)
 *   DELETE /api/vault/:vaultId      -> elimina boveda (header X-Auth-Token)
 *
 * Ejecutar:  node server.js   (HTTPS en puerto 8443)
 * Requiere cert/key.pem y cert/cert.pem (ver README para generarlos).
 */

'use strict';
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.SV_PORT || 8443;
// Layout portable: server.js vive en app/; las bovedas cifradas y el
// certificado se crean en la carpeta raiz de SecureVault (junto al .bat),
// donde el usuario puede verlos y respaldarlos facilmente.
const BASE_DIR = path.join(__dirname, '..');
const DATA_DIR = path.join(BASE_DIR, 'bovedas');
const CERT_DIR = path.join(BASE_DIR, 'cert');
const MAX_BODY = 5 * 1024 * 1024; // 5 MB por boveda
const VAULT_ID_RE = /^[a-f0-9]{64}$/;

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// ---------- utilidades ----------
function sha256Hex(s) {
  return crypto.createHash('sha256').update(s).digest('hex');
}
function vaultPath(id) { return path.join(DATA_DIR, id + '.json'); }

// Cabeceras de seguridad (corregidas tras el escaneo OWASP ZAP del 11-oct-2026)
const SEC_HEADERS = {
  'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
  'Referrer-Policy': 'no-referrer',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Cache-Control': 'no-store'
};

function send(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
    // Sin CORS abierto: la PWA es del mismo origen y la extension usa host_permissions.
    ...SEC_HEADERS
  });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => {
      size += c.length;
      if (size > MAX_BODY) { reject(new Error('BODY_TOO_LARGE')); req.destroy(); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

// Valida que el payload sea SOLO un blob cifrado con la estructura esperada.
// Rechaza cualquier cosa que parezca datos en claro (defensa Zero-Knowledge).
function validEncryptedPayload(p) {
  if (typeof p !== 'object' || p === null) return false;
  const keys = Object.keys(p).sort().join(',');
  if (keys !== 'ct,iv,mac,updatedAt,v') return false;
  if (p.v !== 1) return false;
  if (typeof p.updatedAt !== 'number') return false;
  const b64 = /^[A-Za-z0-9+/]+=*$/;
  if (!b64.test(p.iv) || !b64.test(p.ct) || !b64.test(p.mac)) return false;
  if (Buffer.from(p.iv, 'base64').length !== 12) return false;   // IV AES-GCM
  if (Buffer.from(p.mac, 'base64').length !== 32) return false;  // HMAC-SHA256
  return true;
}

// ---------- registro de auditoria (sin datos sensibles) ----------
function log(...args) {
  console.log(new Date().toISOString(), ...args);
}

// ---------- manejador principal ----------
async function handler(req, res) {
  const url = new URL(req.url, 'https://localhost');
  const parts = url.pathname.split('/').filter(Boolean); // ['api','vault',':id']

  if (req.method === 'OPTIONS') return send(res, 204, {});

  if (req.method === 'GET' && url.pathname === '/api/health') {
    return send(res, 200, { status: 'ok', service: 'SecureVault', zeroKnowledge: true, time: Date.now() });
  }

  // direcciones de acceso en la red local (para la pantalla "Compartir acceso")
  if (req.method === 'GET' && url.pathname === '/api/info') {
    const os = require('os');
    const nets = os.networkInterfaces();
    const ips = [];
    for (const name of Object.keys(nets)) {
      for (const net of nets[name]) {
        if (net.family === 'IPv4' && !net.internal) ips.push(net.address);
      }
    }
    return send(res, 200, { port: PORT, ips });
  }

  if (parts[0] === 'api' && parts[1] === 'vault' && parts[2]) {
    const id = parts[2];
    if (!VAULT_ID_RE.test(id)) return send(res, 400, { error: 'vaultId invalido' });
    const file = vaultPath(id);

    // --- lectura: el blob cifrado es ilegible sin la seed; entregarlo no revela nada ---
    if (req.method === 'GET') {
      if (!fs.existsSync(file)) return send(res, 404, { error: 'Boveda no encontrada' });
      const stored = JSON.parse(fs.readFileSync(file, 'utf8'));
      log('GET vault', id.slice(0, 8) + '…');
      return send(res, 200, { payload: stored.payload, updatedAt: stored.payload.updatedAt });
    }

    // --- escritura y borrado exigen el authToken derivado de la seed ---
    const token = req.headers['x-auth-token'];
    if (!token) return send(res, 401, { error: 'Falta X-Auth-Token' });
    const tokenHash = sha256Hex(token);

    if (req.method === 'PUT') {
      let body;
      try { body = JSON.parse(await readBody(req)); }
      catch (e) {
        if (e.message === 'BODY_TOO_LARGE') return send(res, 413, { error: 'Boveda demasiado grande' });
        return send(res, 400, { error: 'JSON invalido' });
      }
      if (!validEncryptedPayload(body)) {
        log('RECHAZADO: payload no cumple estructura cifrada para', id.slice(0, 8) + '…');
        return send(res, 422, { error: 'Solo se aceptan blobs cifrados con estructura {v, iv, ct, mac, updatedAt}' });
      }
      if (fs.existsSync(file)) {
        const stored = JSON.parse(fs.readFileSync(file, 'utf8'));
        if (!crypto.timingSafeEqual(Buffer.from(stored.authHash, 'hex'), Buffer.from(tokenHash, 'hex'))) {
          return send(res, 403, { error: 'Token de escritura invalido' });
        }
        // proteccion basica contra retroceso de version
        if (body.updatedAt < stored.payload.updatedAt) {
          return send(res, 409, { error: 'Conflicto: existe una version mas reciente', serverUpdatedAt: stored.payload.updatedAt });
        }
      }
      fs.writeFileSync(file, JSON.stringify({ authHash: tokenHash, payload: body }));
      log('PUT vault', id.slice(0, 8) + '…', '(' + Buffer.byteLength(body.ct, 'base64') + ' bytes cifrados)');
      return send(res, 200, { saved: true, updatedAt: body.updatedAt });
    }

    if (req.method === 'DELETE') {
      if (!fs.existsSync(file)) return send(res, 404, { error: 'Boveda no encontrada' });
      const stored = JSON.parse(fs.readFileSync(file, 'utf8'));
      if (!crypto.timingSafeEqual(Buffer.from(stored.authHash, 'hex'), Buffer.from(tokenHash, 'hex'))) {
        return send(res, 403, { error: 'Token invalido: no autorizado para eliminar' });
      }
      // sobrescritura antes de borrar (eliminacion segura del archivo)
      const size = fs.statSync(file).size;
      fs.writeFileSync(file, crypto.randomBytes(size));
      fs.unlinkSync(file);
      log('DELETE vault', id.slice(0, 8) + '…');
      return send(res, 200, { deleted: true });
    }
  }

  // ---------- archivos estaticos de la PWA ----------
  // El mismo servidor sirve la aplicacion en https://localhost:8443/
  if (req.method === 'GET' && !url.pathname.startsWith('/api/')) {
    const PWA_DIR = path.join(__dirname, 'pwa');
    let rel = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
    const file = path.normalize(path.join(PWA_DIR, rel));
    if (!file.startsWith(PWA_DIR)) return send(res, 403, { error: 'Prohibido' }); // anti path-traversal
    if (fs.existsSync(file) && fs.statSync(file).isFile()) {
      const types = { '.html': 'text/html', '.js': 'application/javascript', '.css': 'text/css', '.json': 'application/json', '.png': 'image/png', '.svg': 'image/svg+xml' };
      res.writeHead(200, { 'Content-Type': types[path.extname(file)] || 'application/octet-stream', ...SEC_HEADERS });
      return res.end(fs.readFileSync(file));
    }
  }

  send(res, 404, { error: 'Ruta no encontrada' });
}

// ---------- certificado: se instala solo en el primer arranque ----------
// El .exe trae un certificado embebido (valido 10 anos para localhost).
// Si no existe en disco, se copia automaticamente. Cero comandos para el usuario.
if (!fs.existsSync(path.join(CERT_DIR, 'key.pem'))) {
  fs.mkdirSync(CERT_DIR, { recursive: true });
  const embeddedKey = path.join(__dirname, 'cert-embedded', 'key.pem');
  const embeddedCert = path.join(__dirname, 'cert-embedded', 'cert.pem');
  fs.writeFileSync(path.join(CERT_DIR, 'key.pem'), fs.readFileSync(embeddedKey));
  fs.writeFileSync(path.join(CERT_DIR, 'cert.pem'), fs.readFileSync(embeddedCert));
  log('Certificado instalado por primera vez en ' + CERT_DIR);
}

// ---------- arranque HTTPS ----------
const options = {
  key: fs.readFileSync(path.join(CERT_DIR, 'key.pem')),
  cert: fs.readFileSync(path.join(CERT_DIR, 'cert.pem'))
};

https.createServer(options, (req, res) => {
  handler(req, res).catch(err => {
    log('ERROR:', err.message);
    send(res, 500, { error: 'Error interno' });
  });
}).listen(PORT, () => {
  const url = 'https://localhost:' + PORT;
  // detectar la IP local (WiFi/Ethernet) para el acceso desde celulares
  const os = require('os');
  const nets = os.networkInterfaces();
  const lanIPs = [];
  for (const name of Object.keys(nets)) {
    for (const net of nets[name]) {
      if (net.family === 'IPv4' && !net.internal) lanIPs.push(net.address);
    }
  }
  console.log('');
  console.log('  ================================================');
  console.log('   SecureVault esta funcionando');
  console.log('');
  console.log('   En ESTE computador abre:');
  console.log('       ' + url);
  if (lanIPs.length) {
    console.log('');
    console.log('   En tu CELULAR (misma red WiFi) abre:');
    lanIPs.forEach(ip => console.log('       https://' + ip + ':' + PORT));
  }
  console.log('');
  console.log('   Deja esta ventana abierta mientras lo usas.');
  console.log('  ================================================');
  console.log('');
  log('Bovedas cifradas en: ' + DATA_DIR);
  // abrir el navegador automaticamente
  const { exec } = require('child_process');
  const cmd = process.platform === 'win32' ? 'start "" "' + url + '"'
            : process.platform === 'darwin' ? 'open "' + url + '"'
            : 'xdg-open "' + url + '"';
  exec(cmd, () => {});
});
