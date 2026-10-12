# SecureVault

Gestor de credenciales con arquitectura Zero-Knowledge. La seed de 24 palabras (BIP-39) funciona igual que en una wallet de criptomonedas: es la única llave. La escribes en cualquier dispositivo, se derivan matemáticamente las mismas claves, se descarga la bóveda cifrada del servidor y se descifra localmente. El servidor jamás puede leer nada.

## Componentes

- `server/` Servidor Node.js con HTTPS. Repositorio ciego: almacena blobs cifrados y sirve la PWA. Cero dependencias externas.
- `pwa/` Progressive Web App instalable, con soporte offline (service worker) y cache cifrado local.
- `extension/` Extensión Chrome (Manifest V3) con autofill por dominio.
- `shared/` Módulo criptográfico común (Web Crypto API) y wordlist BIP-39 oficial.
- `tests/` 48 pruebas automatizadas (criptografía, integración cliente-servidor, flujo PWA).

## Flujo criptográfico

```
24 palabras BIP-39 (256 bits de entropía + checksum SHA-256)
   → PBKDF2-HMAC-SHA512, salt "mnemonic", 2048 iter   [estándar BIP-39]
   → seed de 64 bytes
   → HMAC-SHA256(seed, propósito):
        encKey    AES-256-GCM     cifra la bóveda
        macKey    HMAC-SHA256     firma de integridad (se verifica ANTES de descifrar)
        vaultId   hex             identificador público en el servidor
        authToken base64          prueba de escritura (el servidor guarda solo su SHA-256)
```

Contraseña local de acceso rápido: PBKDF2-SHA256 con 150.000 iteraciones y salt de 16 bytes (NIST SP 800-132) envuelve la seed con AES-GCM. Se guarda en el dispositivo; la seed nunca se persiste en claro.

## Puesta en marcha

Requisito: Node.js v20 LTS.

1. Generar el certificado autofirmado (una sola vez):

```bash
cd server
openssl req -x509 -newkey rsa:2048 -keyout cert/key.pem -out cert/cert.pem -days 365 -nodes -subj "/CN=localhost"
```

2. Arrancar el servidor:

```bash
node server.js
```

3. Abrir https://localhost:8443 en Chrome. La primera vez el navegador advierte por el certificado autofirmado: clic en "Avanzado" → "Continuar a localhost". Este paso también habilita las peticiones de la extensión al servidor.

4. Instalar la PWA: en Chrome, icono de instalación en la barra de direcciones (o menú → "Instalar SecureVault"). Queda como app independiente y funciona sin conexión.

## Instalar la extensión

1. Abrir `chrome://extensions`
2. Activar "Modo de desarrollador"
3. "Cargar descomprimida" → seleccionar la carpeta `extension/`
4. Abrir el popup, escribir la seed de 24 palabras y crear la contraseña local del navegador.

En una página con formulario de login, el popup muestra las credenciales que coinciden con el dominio activo y el botón "Rellenar" inserta usuario y contraseña.

## Pruebas

```bash
node tests/test-crypto.js         # 21 pruebas: BIP-39 (incluye vector oficial Trezor), AES-GCM, HMAC, PBKDF2
node tests/test-integration.js    # 18 pruebas: dos dispositivos, servidor ciego, ataques rechazados (servidor corriendo)
node tests/test-pwa-flow.js       # 9 pruebas: offline, backup .svault, rendimiento (servidor corriendo)
```

## Garantías Zero-Knowledge verificables

- El servidor rechaza con 422 cualquier payload que no tenga la estructura exacta de blob cifrado.
- En disco solo existen `{authHash, payload}`: hash del token y datos cifrados. Puede inspeccionarse en `server/data/`.
- Escritura y borrado exigen el authToken derivado de la seed; comparación en tiempo constante.
- Protección anti-retroceso de versión (409 si se intenta subir una bóveda más vieja).
- Eliminación segura: el archivo se sobrescribe con bytes aleatorios antes de borrarse.
- La firma HMAC se verifica antes de cualquier intento de descifrado (detecta manipulación).
- Bloqueo automático a los 10 minutos de inactividad (PWA y extensión).
- Backup `.svault` siempre cifrado; solo se abre con la misma seed.

## Decisión de diseño: sin recuperación

No existe mecanismo de recuperación si se pierde la seed. Es intencional: cualquier vía de recuperación sería también una vía de ataque. Igual que una wallet.

## Licencia

MIT.
