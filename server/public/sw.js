const C='skimms-v2';
self.addEventListener('install',e=>e.waitUntil(caches.open(C).then(c=>c.addAll(['/','/manifest.json','/helmet.html']))));
self.addEventListener('fetch',e=>{const u=new URL(e.request.url);
  if(e.request.method!=='GET'||u.pathname.startsWith('/api')||u.origin!==location.origin)return;   // never cache live data
  e.respondWith(fetch(e.request).catch(()=>caches.match(e.request)))});
