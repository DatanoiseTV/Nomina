// Map: plot geolocated resolved IPs on a world map (Leaflet + OpenStreetMap,
// both vendored/key-less). Requires a GeoLite2/DB-IP City database.

import { api } from "../api.js";
import { h, clear, loadingBlock, toastError } from "../ui.js";

let leafletPromise = null;
function loadLeaflet() {
  if (window.L) return Promise.resolve(window.L);
  if (leafletPromise) return leafletPromise;
  leafletPromise = new Promise((resolve, reject) => {
    if (!document.querySelector("link[data-leaflet]")) {
      const link = document.createElement("link");
      link.rel = "stylesheet";
      link.href = "/vendor/leaflet/leaflet.css";
      link.dataset.leaflet = "1";
      document.head.appendChild(link);
    }
    const s = document.createElement("script");
    s.src = "/vendor/leaflet/leaflet.js";
    s.onload = () => resolve(window.L);
    s.onerror = () => reject(new Error("failed to load the map library"));
    document.head.appendChild(s);
  });
  return leafletPromise;
}

export async function renderMap(root, { registerCleanup }) {
  root.appendChild(loadingBlock());
  let data, L;
  try {
    [data, L] = await Promise.all([api.mapPoints(), loadLeaflet()]);
  } catch (e) {
    toastError(e, "Could not load the map.");
    return;
  }

  clear(root);
  root.appendChild(h("div.page-head", [
    h("div", [h("h1", "Map"), h("div.subtitle", "Where the resolved IP addresses are located.")]),
  ]));

  // "Your data has travelled ~X km" — great-circle distance from this server to
  // every resolved destination, weighted by hits. Live-updates as queries flow.
  let kmEl = null;
  if (data.origin) {
    kmEl = h("span.travel-km", "0");
    root.appendChild(h("div.travel-banner.card", h("div.card-pad", [
      h("span", "Your data has travelled about "),
      kmEl,
      h("span", " km"),
      h("span.travel-origin", ` — from ${data.origin.city || "here"}${data.origin.country ? ", " + data.origin.country : ""}`),
    ])));
    let shown = 0;
    const tweenTo = (target) => {
      const from = shown, t0 = performance.now(), dur = 900;
      const step = (now) => {
        const k = Math.min(1, (now - t0) / dur);
        shown = Math.round(from + (target - from) * (1 - Math.pow(1 - k, 3)));
        kmEl.textContent = shown.toLocaleString();
        if (k < 1) requestAnimationFrame(step);
      };
      requestAnimationFrame(step);
    };
    tweenTo(totalKm(data.origin, data.points));
    // Live refresh: re-fetch and re-tween the counter without rebuilding markers.
    const timer = setInterval(async () => {
      try {
        const fresh = await api.mapPoints();
        if (fresh.origin) tweenTo(totalKm(fresh.origin, fresh.points));
      } catch (_) { /* keep last value */ }
    }, 8000);
    if (registerCleanup) registerCleanup(() => clearInterval(timer));
  }

  if (!data.geoip && !data.asn) {
    root.appendChild(h("div.card", h("div.card-pad", h("div.empty", [
      h("h3", "No GeoIP database"),
      h("p", ["Configure a GeoLite2 or DB-IP City database under ", h("code", "[geo]"),
        " (", h("span.mono", "geoip_db"), " for the map, ", h("span.mono", "asn_db"),
        " for the ASN breakdown)."]),
    ]))));
    return;
  }

  // Build the side column breakdowns (Top countries + Top ASNs).
  const sideCol = h("div.map-side");

  // Top countries (from the located points).
  if (data.geoip) {
    const byCountry = {};
    for (const p of data.points) {
      const c = p.country || "??";
      byCountry[c] = (byCountry[c] || 0) + p.count;
    }
    const rows = Object.entries(byCountry).sort((a, b) => b[1] - a[1]).slice(0, 12);
    sideCol.appendChild(breakdown("Top countries", rows.map(([c, n]) =>
      ({ label: `${flag(c)} ${c}`, n }))));
  }

  // Top ASNs (from the ASN database).
  if (data.asn) {
    sideCol.appendChild(breakdown("Top ASNs", (data.asns || []).map((a) =>
      ({ label: `AS${a.asn}${a.org ? " " + a.org : ""}`, n: a.count })), "asn"));
  }

  // Layout: map + side column when we have locations; side column alone otherwise.
  if (data.geoip) {
    const mapEl = h("div.map-canvas");
    root.appendChild(h("div.map-layout", [h("div.card.map-card", mapEl), sideCol]));

    const map = L.map(mapEl, { worldCopyJump: true }).setView([25, 0], 2);
    L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
      maxZoom: 18, attribution: "© OpenStreetMap contributors",
    }).addTo(map);

    // Marker scale is shared across all layers so sizes are comparable.
    const all = [...(data.points || []), ...(data.blocked || []), ...(data.blocked_clients || [])];
    const maxCount = Math.max(1, ...all.map((p) => p.count));
    const layer = (pts, color, label) => {
      const g = L.layerGroup();
      for (const p of pts || []) {
        const radius = 5 + 16 * Math.sqrt(p.count / maxCount);
        L.circleMarker([p.lat, p.lon], {
          radius, color, weight: 1, fillColor: color, fillOpacity: 0.45,
        })
          .bindPopup(`<b>${label}</b><br>${p.city || "Unknown"}${p.country ? ", " + p.country : ""}<br>${p.count} hit(s)`)
          .addTo(g);
      }
      return g;
    };
    const resolved = layer(data.points, "#818cf8", "Resolved").addTo(map);
    const blocked = layer(data.blocked, "#ef4444", "Blocked destination").addTo(map);
    const blockedClients = layer(data.blocked_clients, "#f59e0b", "Blocked client").addTo(map);
    const overlays = {
      "Resolved": resolved,
      "Blocked destination": blocked,
      "Blocked client": blockedClients,
    };
    // The server's own location (the origin of the distance counter).
    if (data.origin) {
      const home = L.circleMarker([data.origin.lat, data.origin.lon], {
        radius: 8, color: "#10b981", weight: 2, fillColor: "#34d399", fillOpacity: 0.9,
      }).bindPopup(`<b>This server</b><br>${data.origin.city || ""}${data.origin.country ? ", " + data.origin.country : ""}`);
      const homeLayer = L.layerGroup([home]).addTo(map);
      overlays["This server"] = homeLayer;
    }
    L.control.layers(null, overlays, { collapsed: false }).addTo(map);

    setTimeout(() => map.invalidateSize(), 120);
    if (registerCleanup) registerCleanup(() => { try { map.remove(); } catch (_) {} });

    const hits = (data.points || []).reduce((a, p) => a + p.count, 0);
    const bd = (data.blocked || []).reduce((a, p) => a + p.count, 0);
    sideCol.appendChild(h("div.inline-note", { style: "margin-top:8px" },
      `${data.points.length} resolved location(s) · ${hits} hit(s)` +
      (bd ? ` · ${bd} blocked` : "") + `. Tiles © OpenStreetMap.`));
  } else {
    root.appendChild(sideCol);
  }
}

// A titled bar-chart breakdown card. `items` is [{label, n}], sorted by caller.
// `mode` "asn" stacks the (long) label on its own line above the bar so it fits
// the narrow side column; "country" keeps the compact inline layout.
function breakdown(title, items, mode = "country") {
  const max = Math.max(1, ...items.map((i) => i.n));
  const pct = (n) => Math.round((n / max) * 100);
  const rows = items.length
    ? items.map((i) =>
        mode === "asn"
          ? h("div.asn-row", [
              h("div.asn-head", [
                h("span.asn-name", { title: i.label }, i.label),
                h("span.num", String(i.n)),
              ]),
              h("div.bar", h("span", { style: `width:${pct(i.n)}%` })),
            ])
          : h("div.row", [
              h("span.mono", i.label),
              h("div.bar", h("span", { style: `width:${pct(i.n)}%` })),
              h("span.num", String(i.n)),
            ]))
    : [h("div.inline-note", "No data yet.")];
  return h("div.section", { style: "margin-bottom:16px" }, [
    h("h2", { style: "margin:0 0 12px" }, title),
    h("div.card.map-side-card", h("div.card-pad", h("div.qtype-bar", rows))),
  ]);
}

// Great-circle distance (km) between two {lat,lon} points.
function haversine(a, b) {
  const R = 6371, rad = (d) => (d * Math.PI) / 180;
  const dLat = rad(b.lat - a.lat), dLon = rad(b.lon - a.lon);
  const h = Math.sin(dLat / 2) ** 2 +
    Math.cos(rad(a.lat)) * Math.cos(rad(b.lat)) * Math.sin(dLon / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(h));
}

// Total km from the origin to every resolved destination, weighted by hits.
function totalKm(origin, points) {
  if (!origin) return 0;
  let sum = 0;
  for (const p of points || []) sum += haversine(origin, p) * (p.count || 1);
  return Math.round(sum);
}

// ISO-3166 alpha-2 -> regional-indicator flag emoji.
function flag(cc) {
  if (!cc || cc.length !== 2 || !/^[A-Za-z]{2}$/.test(cc)) return "🏳";
  return String.fromCodePoint(...[...cc.toUpperCase()].map((ch) => 0x1f1e6 + ch.charCodeAt(0) - 65));
}
