/**
 * EquiScan Pro — Service Worker v1
 * Estratégia: cache-first para assets estáticos, network-first para API
 * Suporte offline parcial: app carrega, análise requer ligação
 */

const CACHE_NAME    = 'equiscan-v1';
const OFFLINE_URL   = '/offline.html';
const API_PREFIX    = '/api/';

// Assets para pré-cache (instalação)
const PRECACHE_ASSETS = [
  '/',
  '/manifest.json',
  'https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700&family=Lora:ital,wght@0,400;0,600;1,400&family=JetBrains+Mono:wght@400;500&display=swap'
];

// ── INSTALL ──────────────────────────────────────────────────────────────────
self.addEventListener('install', event => {
  console.log('[SW] Installing EquiScan Service Worker');
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => {
        // Pré-cachear recursos críticos (silently — não falha se algum não existir)
        return Promise.allSettled(
          PRECACHE_ASSETS.map(url =>
            cache.add(url).catch(e => console.warn('[SW] Pre-cache failed:', url, e.message))
          )
        );
      })
      .then(() => self.skipWaiting())
  );
});

// ── ACTIVATE ─────────────────────────────────────────────────────────────────
self.addEventListener('activate', event => {
  console.log('[SW] Activating EquiScan Service Worker');
  event.waitUntil(
    caches.keys().then(keys =>
      Promise.all(
        keys
          .filter(key => key !== CACHE_NAME)
          .map(key => {
            console.log('[SW] Deleting old cache:', key);
            return caches.delete(key);
          })
      )
    ).then(() => self.clients.claim())
  );
});

// ── FETCH ────────────────────────────────────────────────────────────────────
self.addEventListener('fetch', event => {
  const { request } = event;
  const url = new URL(request.url);

  // 1. Chamadas API → sempre network (nunca cache)
  if (url.pathname.startsWith(API_PREFIX)) {
    event.respondWith(networkOnly(request));
    return;
  }

  // 2. Anthropic API (externo) → sempre network
  if (url.hostname.includes('anthropic.com') || url.hostname.includes('supabase.co')) {
    event.respondWith(networkOnly(request));
    return;
  }

  // 3. Navegação (HTML) → network-first, fallback cache, fallback offline
  if (request.mode === 'navigate') {
    event.respondWith(networkFirstWithOfflineFallback(request));
    return;
  }

  // 4. Fontes Google → cache-first (persistentes)
  if (url.hostname.includes('fonts.googleapis.com') || url.hostname.includes('fonts.gstatic.com')) {
    event.respondWith(cacheFirst(request));
    return;
  }

  // 5. Outros assets estáticos → stale-while-revalidate
  event.respondWith(staleWhileRevalidate(request));
});

// ── ESTRATÉGIAS ──────────────────────────────────────────────────────────────

async function networkOnly(request) {
  try {
    return await fetch(request);
  } catch (e) {
    return new Response(JSON.stringify({ error: 'Sem ligação à internet', offline: true }), {
      status: 503,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

async function networkFirstWithOfflineFallback(request) {
  try {
    const response = await fetch(request);
    // Guardar em cache para próxima vez
    if (response.ok) {
      const cache = await caches.open(CACHE_NAME);
      cache.put(request, response.clone());
    }
    return response;
  } catch (e) {
    // Tentar cache
    const cached = await caches.match(request);
    if (cached) return cached;
    // Fallback offline
    const offlineCached = await caches.match('/');
    if (offlineCached) return offlineCached;
    return new Response('EquiScan Pro — Sem ligação. Reconecta para continuar.', {
      status: 503,
      headers: { 'Content-Type': 'text/plain; charset=utf-8' }
    });
  }
}

async function cacheFirst(request) {
  const cached = await caches.match(request);
  if (cached) return cached;
  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(CACHE_NAME);
      cache.put(request, response.clone());
    }
    return response;
  } catch (e) {
    return new Response('', { status: 503 });
  }
}

async function staleWhileRevalidate(request) {
  const cache  = await caches.open(CACHE_NAME);
  const cached = await cache.match(request);
  const fetchPromise = fetch(request).then(response => {
    if (response.ok) cache.put(request, response.clone());
    return response;
  }).catch(() => null);
  return cached || (await fetchPromise) || new Response('', { status: 503 });
}

// ── BACKGROUND SYNC — flush offline queue quando voltar a ligar ──────────────
self.addEventListener('sync', event => {
  if (event.tag === 'eq-sync-queue') {
    event.waitUntil(
      self.clients.matchAll().then(clients => {
        clients.forEach(client => client.postMessage({ type: 'SYNC_REQUESTED' }));
      })
    );
  }
});

// ── PUSH NOTIFICATIONS (futuro) ──────────────────────────────────────────────
self.addEventListener('push', event => {
  if (!event.data) return;
  const data = event.data.json();
  event.waitUntil(
    self.registration.showNotification(data.title || 'EquiScan Pro', {
      body:    data.body    || '',
      icon:    '/icons/icon-192.png',
      badge:   '/icons/icon-72.png',
      tag:     data.tag     || 'equiscan',
      data:    data.url     || '/',
      vibrate: [100, 50, 100]
    })
  );
});

self.addEventListener('notificationclick', event => {
  event.notification.close();
  event.waitUntil(clients.openWindow(event.notification.data || '/'));
});
