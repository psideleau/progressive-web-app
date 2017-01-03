var cacheName = 'weatherPWA-v9';
var dataCache = 'weather-data-cache';
var weatherAPIUrlBase = 'https://publicdata-weather.firebaseio.com/';
var filesToCache = [
    '/',
    '/index.html',
    '/scripts/app.js',
    '/scripts/localforage.js',
    '/styles/ud811.css',
    '/images/clear.png',
    '/images/cloudy-scattered-showers.png',
    '/images/cloudy.png',
    '/images/fog.png',
    '/images/ic_add_white_24px.svg',
    '/images/ic_refresh_white_24px.svg',
    '/images/partly-cloudy.png',
    '/images/rain.png',
    '/images/scattered-showers.png',
    '/images/sleet.png',
    '/images/snow.png',
    '/images/thunderstorm.png',
    '/images/wind.png'
];

self.addEventListener('install', function(e) {
    console.log('[ServiceWorker] Install');
    e.waitUntil(
        caches.open(cacheName).then(function(cache) {
            console.log('[ServiceWorker] Caching app shell');
            return cache.addAll(filesToCache);
        })
    );
});

self.addEventListener('activate', function(e) {
    console.log('[ServiceWorker] Activated');
    e.waitUntil(
        caches.keys().then(function(keyList) {
            return Promise.all(keyList.map(function(key) {
                if (key !== cacheName && key !== dataCache) {
                    console.log('[ServiceWorker] Removing old cache', key);
                    return caches.delete(key);
                }
            }));
        })
    );
});

self.addEventListener('push', function(event) {
    console.log('[Service Worker] Push Received.');
    console.log(`[Service Worker] Push had this data: "${event.data.text()}"`);

    const title = 'Push Codelab';
    const options = {
        body: 'Yay it works.' + event.data,
        icon: 'images/icon.png',
        badge: 'images/badge.png'
    };

    event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', function(event) {
    console.log('[Service Worker] Notification click Received.');

    event.notification.close();

    event.waitUntil(
        clients.openWindow('https://developers.google.com/web/')
    );
});

self.addEventListener('fetch', function(e) {
    if (e.request.url.startsWith(weatherAPIUrlBase)) {
        console.log("Fetching data")
        e.respondWith(
            fetch(e.request)
                .then(function (response) {
                    return caches.open(dataCache).then(function (cache) {
                        cache.put(e.request.url, response.clone());
                        console.log('[ServiceWorker] Data Cached', e.request.url);
                        return response;
                    })
                    .catch(function (err) {
                        console.log(err.message)
                    });
                })
        );
    }
    else {
        console.log('[ServiceWorker] Fetching url and cache', e.request.url, caches);
        e.respondWith(
            caches.match(e.request).then(function (response) {
                if (response) {
                    console.log("Found caching page", e.request.url)
                }
                else {
                    console.log(" not cached response", e.request.url)
                }
                return response || fetch(e.request);
            })
            .catch(function (err) {
                console.log(err.message)
            })
        );
    }
});