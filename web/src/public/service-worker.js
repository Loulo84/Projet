// public/service-worker.js
const CACHE = "rentchain-v2";
const ASSETS = ["/", "/index.html"];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(ASSETS)));
});
self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys().then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
  );
});
self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  const isAPI = url.pathname.startsWith("/api/");
  const isSSE = e.request.headers.get("accept") === "text/event-stream";
  if (isAPI || isSSE) return; // ne jamais intercepter l'API/SSE

  if (url.origin === location.origin && e.request.method === "GET") {
    e.respondWith(
      caches.match(e.request).then((res) =>
        res ||
        fetch(e.request).then((r) => {
          const copy = r.clone();
          caches.open(CACHE).then((c) => c.put(e.request, copy));
          return r;
        }).catch(() => res)
      )
    );
  }
});
