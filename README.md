# SecureVault

Gestor de contraseñas Zero-Knowledge hecho para la empresa Novedades Gladys (Santa Marta). Proyecto de grado de Ingeniería de Sistemas, Universidad Antonio Nariño.

Autor: Jesús David Romero Witt. Licencia MIT.

## Qué es

El servidor nunca ve tus contraseñas. Todo se cifra en el dispositivo del usuario antes de enviarse y el servidor solo guarda un bloque cifrado que no puede leer ("servidor ciego").

## Cómo funciona la seguridad

- Seed de 24 palabras (BIP-39). Es la única llave de la bóveda.
- De la seed se derivan 4 claves con PBKDF2-HMAC-SHA512 y HMAC-SHA256: clave de cifrado, clave de integridad, id de bóveda y token de autenticación.
- Cifrado AES-256-GCM más HMAC-SHA256 (se verifica el HMAC antes de descifrar).
- El servidor solo guarda el hash SHA-256 del token y rechaza payloads mal formados (422), tokens malos (401/403) y versiones viejas (409, anti-rollback).
- Contraseña local opcional con PBKDF2-SHA256 de 150.000 iteraciones y bloqueo automático a los 10 minutos.

Nota: es Zero-Knowledge de arquitectura (el servidor no tiene las claves). No usa pruebas de conocimiento cero (ZKP).

## Qué incluye

- `app/server.js`: servidor HTTPS en Node.js (puerto 8443), rutas `PUT/GET /vault/:id`.
- `app/pwa/`: aplicación web progresiva con modo offline (Service Worker) y sincronización con fusión de cambios.
- `extension/`: extensión de Chrome (Manifest V3) con autocompletado por dominio. Solo navegadores Chromium.
- `desarrollo/`: módulo criptográfico fuente, documentación de arquitectura y pruebas automatizadas (71).

## Cómo correrlo

Necesitas Node.js 18 o superior.

1. Genera un certificado local (una sola vez):

```
mkdir cert
openssl req -x509 -newkey rsa:2048 -nodes -keyout cert/key.pem -out cert/cert.pem -days 365 -subj "/CN=localhost"
```

2. Inicia el servidor:

```
node app/server.js
```

3. Abre `https://localhost:8443`. Chrome va a avisar que la conexión no es privada porque el certificado es local. Continúa a localhost.

En Windows también se puede usar `INICIAR-SecureVault.bat` si pones `node.exe` en la carpeta `runtime/`.

## Pruebas

Con el servidor corriendo:

```
node desarrollo/tests/test-crypto.js
node desarrollo/tests/test-integration.js
node desarrollo/tests/test-pwa-flow.js
node desarrollo/tests/test-merge.js
node desarrollo/tests/test-browser-env.js
```

## Aviso

Si pierdes la seed de 24 palabras nadie puede recuperar la bóveda. Es a propósito.

## Licencia

MIT. Mira el archivo `LICENSE`.
