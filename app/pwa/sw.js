/* SecureVault - Service Worker
   Estrategia: cache-first para el shell de la app (funciona 100% offline).
   Las llamadas a /api/ van siempre a red; la app maneja el modo offline
   con su propio cache CIFRADO en localStorage. */
const CACHE = 'securevault-v8';
const SHELL = ['./', './index.html', './styles.css', './app.js', './crypto.js', './qr.js', './wordlist.js', './manifest.json', './icons/icon-192.png', './icons/icon-512.png'];

self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', e => {
  e.waitUntil(caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (url.pathname.includes('/api/')) return; // nunca cachear la API
  e.respondWith(caches.match(e.request).then(hit => hit || fetch(e.request)));
});
