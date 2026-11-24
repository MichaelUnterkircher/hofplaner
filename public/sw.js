// Minimaler Service Worker: macht die App installierbar, speichert bewusst nichts zwischen (Daten sind immer live).
self.addEventListener('install',()=>self.skipWaiting());
self.addEventListener('activate',e=>e.waitUntil(self.clients.claim()));
self.addEventListener('fetch',()=>{});
