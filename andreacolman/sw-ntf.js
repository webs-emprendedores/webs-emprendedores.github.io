/* aviso de turno (notif_turnos.py): muestra el aviso que manda la función de Netlify y abre la página al tocarlo */
self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('push', e => { let d = {}; try { d = e.data ? e.data.json() : {}; } catch (err) { d = { title: 'Tu turno', body: e.data ? e.data.text() : '' }; }
  e.waitUntil(self.registration.showNotification(d.title || 'Tu turno', { body: d.body || '', icon: 'icon-192.png', badge: 'icon-192.png', data: { url: d.url || './' } })); });
self.addEventListener('notificationclick', e => { e.notification.close(); const u = (e.notification.data && e.notification.data.url) || './';
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then(cs => { const c = cs.find(x => x.url.split('#')[0] === u.split('#')[0]); return c ? c.navigate(u).then(w => (w || c).focus()).catch(() => self.clients.openWindow(u)) : self.clients.openWindow(u); })); });   /* tocar el aviso abre su turno (17/11 23:34) */
