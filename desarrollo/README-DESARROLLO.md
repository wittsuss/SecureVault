# Carpeta de desarrollo (para la tesis)

No es necesaria para usar SecureVault. Contiene:

- `shared/` Modulo criptografico fuente y wordlist BIP-39 oficial.
- `tests/` 70 pruebas automatizadas.

Ejecutar pruebas (con SecureVault iniciado):

    ..\runtime\node.exe tests\test-crypto.js
    ..\runtime\node.exe tests\test-integration.js
    ..\runtime\node.exe tests\test-pwa-flow.js

En Linux/Mac o con Node instalado: `node tests/test-crypto.js`, etc.

Suites:
- test-browser-env: simula el entorno del navegador (sin require)
  y verifica la carga de scripts y el flujo de creacion de boveda.
  10 pruebas. No requiere servidor.
- test-crypto: BIP-39 (incluye vector oficial Trezor), AES-256-GCM,
  HMAC-SHA256, PBKDF2, deteccion de manipulacion. 21 pruebas.
- test-integration: dos dispositivos con la misma seed, servidor ciego
  verificado en disco, ataques rechazados (403/422/409), eliminacion
  segura. 18 pruebas.
- test-pwa-flow: contrasena local, modo offline, backup .svault,
  rendimiento RNF-003 (500 entradas < 2 s). 9 pruebas.
