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

  if (!data.geoip) {
    root.appendChild(h("div.card", h("div.card-pad", h("div.empty", [
      h("h3", "No GeoIP City database"),
      h("p", ["Configure a GeoLite2 or DB-IP City database under ", h("code", "[geo]"),
        " (", h("span.mono", "geoip_db"), ") to plot resolved IPs on the map."]),
    ]))));
    return;
  }

  const mapEl = h("div.map-canvas");
  root.appendChild(h("div.card.map-card", mapEl));
  const hits = data.points.reduce((a, p) => a + p.count, 0);
  root.appendChild(h("div.inline-note", { style: "margin-top:8px" },
    `${data.points.length} location(s) · ${hits} resolved-IP hit(s). Tiles © OpenStreetMap.`));

  const map = L.map(mapEl, { worldCopyJump: true }).setView([25, 0], 2);
  L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
    maxZoom: 18, attribution: "© OpenStreetMap contributors",
  }).addTo(map);

  const maxCount = Math.max(1, ...data.points.map((p) => p.count));
  for (const p of data.points) {
    const radius = 5 + 16 * Math.sqrt(p.count / maxCount);
    L.circleMarker([p.lat, p.lon], {
      radius, color: "#818cf8", weight: 1, fillColor: "#818cf8", fillOpacity: 0.45,
    })
      .addTo(map)
      .bindPopup(`<b>${p.city || "Unknown"}${p.country ? ", " + p.country : ""}</b><br>${p.count} hit(s)`);
  }
  // Leaflet needs a size recalc once the element has its final layout.
  setTimeout(() => map.invalidateSize(), 120);
  if (registerCleanup) registerCleanup(() => { try { map.remove(); } catch (_) {} });

  // Top countries breakdown below the map.
  const byCountry = {};
  for (const p of data.points) {
    const c = p.country || "??";
    byCountry[c] = (byCountry[c] || 0) + p.count;
  }
  const rows = Object.entries(byCountry).sort((a, b) => b[1] - a[1]).slice(0, 12);
  const max = Math.max(1, ...rows.map((r) => r[1]));
  root.appendChild(h("div.section", { style: "margin-top:18px" }, [
    h("h2", { style: "margin-bottom:12px" }, "Top countries"),
    h("div.card", h("div.card-pad", rows.length
      ? h("div.qtype-bar", rows.map(([c, n]) =>
          h("div.row", [
            h("span.mono", `${flag(c)} ${c}`),
            h("div.bar", h("span", { style: `width:${Math.round((n / max) * 100)}%` })),
            h("span.num", String(n)),
          ])))
      : h("div.inline-note", "No data yet."))),
  ]));
}

// ISO-3166 alpha-2 -> regional-indicator flag emoji.
function flag(cc) {
  if (!cc || cc.length !== 2 || !/^[A-Za-z]{2}$/.test(cc)) return "🏳";
  return String.fromCodePoint(...[...cc.toUpperCase()].map((ch) => 0x1f1e6 + ch.charCodeAt(0) - 65));
}
