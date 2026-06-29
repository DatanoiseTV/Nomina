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

    const maxCount = Math.max(1, ...data.points.map((p) => p.count));
    for (const p of data.points) {
      const radius = 5 + 16 * Math.sqrt(p.count / maxCount);
      L.circleMarker([p.lat, p.lon], {
        radius, color: "#818cf8", weight: 1, fillColor: "#818cf8", fillOpacity: 0.45,
      })
        .addTo(map)
        .bindPopup(`<b>${p.city || "Unknown"}${p.country ? ", " + p.country : ""}</b><br>${p.count} hit(s)`);
    }
    setTimeout(() => map.invalidateSize(), 120);
    if (registerCleanup) registerCleanup(() => { try { map.remove(); } catch (_) {} });

    const hits = data.points.reduce((a, p) => a + p.count, 0);
    sideCol.appendChild(h("div.inline-note", { style: "margin-top:8px" },
      `${data.points.length} location(s) · ${hits} hit(s). Tiles © OpenStreetMap.`));
  } else {
    root.appendChild(sideCol);
  }
}

// A titled bar-chart breakdown card. `items` is [{label, n}], sorted by caller.
function breakdown(title, items, mono = "country") {
  const max = Math.max(1, ...items.map((i) => i.n));
  return h("div.section", { style: "margin-bottom:16px" }, [
    h("h2", { style: "margin:0 0 12px" }, title),
    h("div.card.map-side-card", h("div.card-pad", items.length
      ? h("div.qtype-bar", items.map((i) =>
          h("div.row", [
            h("span.mono", { title: i.label, style: mono === "asn" ? "max-width:55%;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" : null }, i.label),
            h("div.bar", h("span", { style: `width:${Math.round((i.n / max) * 100)}%` })),
            h("span.num", String(i.n)),
          ])))
      : h("div.inline-note", "No data yet."))),
  ]);
}

// ISO-3166 alpha-2 -> regional-indicator flag emoji.
function flag(cc) {
  if (!cc || cc.length !== 2 || !/^[A-Za-z]{2}$/.test(cc)) return "🏳";
  return String.fromCodePoint(...[...cc.toUpperCase()].map((ch) => 0x1f1e6 + ch.charCodeAt(0) - 65));
}
