// Discovered: live view of the *.local hosts learned via mDNS and the zone
// they are republished under. Read-only; mDNS is enabled in the [mdns] config.

import { api } from "../api.js";
import { h, clear, loadingBlock, toastError } from "../ui.js";

const POLL_MS = 5000;

export async function renderMdns(root, { registerCleanup }) {
  root.appendChild(loadingBlock());
  let data;
  try {
    data = await api.mdns();
  } catch (e) {
    toastError(e, "Could not load mDNS discovery.");
    return;
  }

  clear(root);
  root.appendChild(h("div.page-head", [
    h("div", [
      h("h1", "Discovered"),
      h("div.subtitle", "LAN hosts learned via mDNS and republished under your zone."),
    ]),
  ]));

  const body = h("div#mdns-body");
  root.appendChild(body);
  paint(body, data);

  // Live refresh so newly-announced hosts appear without a manual reload.
  const timer = setInterval(async () => {
    try {
      paint(body, await api.mdns());
    } catch (_) {
      /* keep last good view on a transient error */
    }
  }, POLL_MS);
  if (registerCleanup) registerCleanup(() => clearInterval(timer));
}

function paint(body, data) {
  clear(body);

  if (!data.enabled) {
    body.appendChild(h("div.card", h("div.card-pad", h("div.empty", [
      h("h3", "mDNS discovery is off"),
      h("p", ["Enable it in the ", h("code", "[mdns]"), " section of your config — set ",
        h("span.mono", "enabled = true"), " and a ", h("span.mono", "zone"),
        " (e.g. ", h("span.mono", "lan"), "), then restart. It binds UDP 5353 and ",
        "coexists with a system responder."]),
    ]))));
    return;
  }

  body.appendChild(h("div.grid.grid-cards", { style: "margin-bottom:16px" }, [
    statCard("Publish zone", data.zone ? "." + data.zone : "—"),
    statCard("Record TTL", data.ttl + "s"),
    statCard("Hosts learned", String(data.hosts.length)),
  ]));

  if (!data.hosts.length) {
    body.appendChild(h("div.card", h("div.card-pad", h("div.empty", [
      h("h3", "No hosts discovered yet"),
      h("p", ["Discovery is passive: hosts appear as devices announce themselves or ",
        "respond to queries on the LAN. On a quiet network this can take a moment."]),
    ]))));
    return;
  }

  const rows = data.hosts.map((host) =>
    h("tr", [
      h("td", h("span.mono", host.host)),
      h("td", host.published ? h("span.mono", host.published) : h("span.inline-note", "—")),
      h("td", host.addresses.length
        ? h("div", { style: "display:flex;flex-wrap:wrap;gap:6px" },
            host.addresses.map((a) => h("span.badge.badge-muted.mono", a)))
        : h("span.inline-note", "—")),
      h("td.num", host.ttl + "s"),
    ])
  );

  body.appendChild(h("div.card", h("div.table-wrap",
    h("table.table", [
      h("thead", h("tr", [
        h("th", "Host (.local)"),
        h("th", "Published as"),
        h("th", "Addresses"),
        h("th.num", "Expires in"),
      ])),
      h("tbody", rows),
    ])
  )));
}

function statCard(label, value) {
  return h("div.stat", [
    h("div.label", label),
    h("div.value", value),
  ]);
}
