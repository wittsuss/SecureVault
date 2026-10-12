/*
 * SecureVault - background service worker (MV3)
 * Es efimero por diseno. Su unica funcion es el auto-bloqueo:
 * revisa periodicamente si la sesion supero los 10 minutos y la limpia.
 * No guarda ni procesa material criptografico.
 */
const LOCK_MS = 10 * 60 * 1000;

chrome.runtime.onInstalled.addListener(() => {
  chrome.alarms.create('sv-autolock', { periodInMinutes: 1 });
});
chrome.alarms?.onAlarm.addListener(async alarm => {
  if (alarm.name !== 'sv-autolock') return;
  const { sv_session } = await chrome.storage.session.get('sv_session');
  if (sv_session && (Date.now() - sv_session.unlockedAt) >= LOCK_MS) {
    await chrome.storage.session.clear();
  }
});
