/* PRUEBA TURNOS: service worker único de la página. Recibe los avisos de Firebase (mensajes solo de datos) y arma la notificación;
   así no hace falta el service worker de Firebase y no choca con este. */
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('push', e => {
  let d = {}; try{ d = e.data ? e.data.json() : {}; }catch(x){ d = {title: 'Turno nuevo', body: e.data ? e.data.text() : ''}; }
  const m = d.data || d;   // FCM manda {data:{...}}; un push propio puede mandar {title, body}
  e.waitUntil(self.registration.showNotification(m.title || 'Turno nuevo', {body: m.body || '', tag: 'pt-turno', renotify: true, data: {url: m.url || './#panel'}}));
});
self.addEventListener('notificationclick', e => { e.notification.close(); const u = new URL((e.notification.data && e.notification.data.url) || './#panel', self.registration.scope).href;
  e.waitUntil(self.clients.matchAll({type: 'window', includeUncontrolled: true}).then(l => { const c = l.find(x => x.url.split('#')[0] === u.split('#')[0]); return c ? c.focus().then(w => w && w.navigate(u)) : self.clients.openWindow(u); })); });
