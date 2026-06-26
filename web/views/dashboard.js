// Dashboard: status cards + live query stats.

import { api } from "../api.js";
import {
  h, clear, badge, fmtInt, fmtUptime, fmtTime, fmtClock,
  loadingBlock, emptyState,
} from "../ui.js";

const POLL_MS = 5000;

const OUTCOME_KIND = {
  authoritative: "accent",
  cached: "muted",
  forwarded: "accent",
  nxdomain: "warn",
  refused: "danger",
  servfail: "danger",
};

const RCODE_KIND = {
  NOERROR: "on",
  NXDOMAIN: "warn",
  SERVFAIL: "danger",
  REFUSED: "danger",
};

export async function renderDashboard(root, { registerCleanup }) {
  root.appendChild(loadingBlock());

  let status;
  try {
    status = await api.status();
  } catch (e) {
    throw e; // router handles 401 / shows retry
  }

  const statsHost = h("div");
  const recentHost = h("div");

  clear(root).appendChild(
    h("div", [
      h("div.page-head", [
        h("div", [h("h1", "Dashboard"), h("div.subtitle", `PicoNS ${status.version}`)]),
      ]),

      // status cards
      h("div.grid.grid-cards.section", [
        statCard("Zones", fmtInt(status.zone_count)),
        statCard("Records", fmtInt(status.record_count)),
        statCard("Views", fmtInt(status.view_count)),
        statCard("Uptime", fmtUptime(status.uptime_seconds),
          status.started_at ? `since ${fmtTime(status.started_at)}` : null),
      ]),

      // listeners
      h("div.card.section", [
        h("div.card-head", [h("h2", "Listeners")]),
        h("div.card-pad", listenersView(status.listeners || [])),
      ]),

      // live stats
      statsHost,
      recentHost,
    ])
  );

  // --- live stats polling ---
  let timer = null;
  let stopped = false;

  async function poll() {
    if (stopped) return;
    try {
      const stats = await api.stats();
      if (stopped) return;
      renderStats(statsHost, stats);
      renderRecent(recentHost, stats.recent || []);
    } catch (e) {
      // transient; keep prior render. A dead session ends polling and bounces to login.
      if (e && e.status === 401) {
        cleanup();
        window.dispatchEvent(new CustomEvent("picons:unauthorized"));
        return;
      }
    }
    if (!stopped) timer = setTimeout(poll, POLL_MS);
  }

  function cleanup() {
    stopped = true;
    if (timer) clearTimeout(timer);
  }
  if (registerCleanup) registerCleanup(cleanup);

  await poll();
}

function statCard(label, value, sub) {
  return h("div.stat", [
    h("div.label", label),
    h("div.value", value),
    sub ? h("div.sub", sub) : null,
  ]);
}

function listenersView(listeners) {
  if (!listeners.length) return h("div.inline-note", "No listeners reported.");
  return h("div.grid.grid-cards",
    listeners.map((l) =>
      h("div.card.card-pad", { style: "box-shadow:none" }, [
        h("div", { style: "display:flex;align-items:center;gap:8px;justify-content:space-between" }, [
          h("strong", { style: "text-transform:uppercase;letter-spacing:0.03em" }, l.kind),
          l.enabled
            ? badge("on", "on")
            : badge("off", "off"),
        ]),
        h("div.mono", { style: "color:var(--text-muted);margin-top:6px;font-size:0.85rem" }, l.addr),
      ])
    )
  );
}

function renderStats(host, stats) {
  const counters = [
    ["Total", stats.total],
    ["Authoritative", stats.authoritative],
    ["Forwarded", stats.forwarded],
    ["Cached", stats.cached],
    ["NXDOMAIN", stats.nxdomain],
    ["Refused", stats.refused],
    ["SERVFAIL", stats.servfail],
  ];

  const qtypes = Object.entries(stats.by_qtype || {}).sort((a, b) => b[1] - a[1]);
  const max = qtypes.reduce((m, [, v]) => Math.max(m, v), 0) || 1;

  clear(host).appendChild(
    h("div.section", [
      h("h2", { style: "margin-bottom:12px" }, "Query statistics"),
      h("div.grid.grid-cards", { style: "margin-bottom:16px" },
        counters.map(([label, val]) =>
          h("div.stat", [h("div.label", label), h("div.value", fmtInt(val))])
        )
      ),
      h("div.card", [
        h("div.card-head", [h("h2", "By query type")]),
        h("div.card-pad",
          qtypes.length
            ? h("div.qtype-bar",
                qtypes.map(([t, v]) =>
                  h("div.row", [
                    h("span.mono", t),
                    h("div.bar", h("span", { style: `width:${Math.round((v / max) * 100)}%` })),
                    h("span.num", fmtInt(v)),
                  ])
                )
              )
            : h("div.inline-note", "No queries yet.")
        ),
      ]),
    ])
  );
}

function renderRecent(host, recent) {
  const head = h("div.card-head", [
    h("h2", "Recent queries"),
    h("div.spacer"),
    h("span.inline-note", "live"),
  ]);

  let bodyNode;
  if (!recent.length) {
    bodyNode = emptyState("inbox", "No recent queries", "Queries will appear here as clients resolve names.");
  } else {
    bodyNode = h("div.table-wrap", { style: "max-height:420px;border:none" },
      h("table.tbl", [
        h("thead", h("tr", [
          h("th", "Time"), h("th", "Client"), h("th", "View"),
          h("th", "Name"), h("th", "Type"), h("th", "Outcome"), h("th", "RCODE"),
        ])),
        h("tbody", recent.map((q) =>
          h("tr", [
            h("td.mono", fmtClock(q.at)),
            h("td.mono", q.client),
            h("td", q.view || h("span.inline-note", "-")),
            h("td.mono.wrap", q.name),
            h("td.mono", q.qtype),
            h("td", badge(q.outcome, OUTCOME_KIND[q.outcome] || "muted")),
            h("td", badge(q.rcode, RCODE_KIND[q.rcode] || "muted")),
          ])
        )),
      ])
    );
  }

  clear(host).appendChild(
    h("div.card.section", [head, bodyNode])
  );
}
