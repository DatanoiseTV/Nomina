// Dashboard: status cards + live query stats.

import { api } from "../api.js";
import {
  h, clear, badge, fmtInt, fmtUptime, fmtTime, fmtClock,
  loadingBlock, emptyState, confirmDialog, toast, toastError,
} from "../ui.js";

const POLL_MS = 5000;

const OUTCOME_KIND = {
  authoritative: "accent",
  cached: "muted",
  forwarded: "accent",
  rewritten: "accent",
  blocked: "warn",
  nxdomain: "warn",
  refused: "danger",
  servfail: "danger",
};

const RESOLUTION_LABEL = {
  forward: "Forward",
  recursive: "Recursive",
  off: "Authoritative-only",
};

// Full names for listener kinds; the row shows the short uppercase code with
// this as a tooltip. Unknown kinds fall back to the raw code.
const LISTENER_LABEL = {
  udp: "DNS over UDP",
  tcp: "DNS over TCP",
  dot: "DNS-over-TLS",
  doh: "DNS-over-HTTPS",
  doq: "DNS-over-QUIC",
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
  const topHost = h("div");
  const recentHost = h("div");

  clear(root).appendChild(
    h("div", [
      h("div.page-head", [
        h("div", { style: "display:flex;align-items:center;gap:10px;flex-wrap:wrap" }, [
          h("h1", "Dashboard"),
          status.resolution_mode
            ? badge(`Resolution: ${RESOLUTION_LABEL[status.resolution_mode] || status.resolution_mode}`, "accent")
            : null,
        ]),
        h("div.subtitle", `PicoNS ${status.version}`),
      ]),

      // status cards
      h("div.grid.grid-cards.section", [
        statCard("Zones", fmtInt(status.zone_count),
          status.active_zone_count != null ? `${fmtInt(status.active_zone_count)} active` : null),
        statCard("Records", fmtInt(status.record_count)),
        statCard("Views", fmtInt(status.view_count)),
        statCard("Blocked domains", fmtInt(status.blocked_domains)),
        statCard("Rewrites", fmtInt(status.rewrite_count)),
        status.conditional_forward_count != null
          ? statCard("Conditional forwards", fmtInt(status.conditional_forward_count))
          : null,
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
      topHost,
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
      renderTop(topHost, stats);
      renderRecent(recentHost, stats, refreshNow);
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

  // Re-poll immediately (used after a Clear log action), without stacking timers.
  async function refreshNow() {
    if (stopped) return;
    if (timer) clearTimeout(timer);
    await poll();
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
          h("strong", { style: "text-transform:uppercase;letter-spacing:0.03em", title: LISTENER_LABEL[l.kind] || l.kind }, l.kind),
          l.enabled
            ? badge("on", "on")
            : badge("off", "off"),
        ]),
        h("div.mono", { style: "color:var(--text-muted);margin-top:6px;font-size:0.85rem" }, l.addr),
      ])
    )
  );
}

function fmtQps(n) {
  const v = Number(n);
  if (!isFinite(v)) return "0.0";
  return v.toFixed(v >= 100 ? 0 : 1);
}

// Inline SVG bar chart for the per-second series. Built as an SVG string (no
// external resources); fills come from CSS so it follows the theme.
function sparkline(series) {
  const data = (series || []).map((n) => Math.max(0, Number(n) || 0));
  const W = 600, H = 80;
  const n = data.length || 1;
  const max = data.reduce((m, v) => Math.max(m, v), 0) || 1;
  const barW = W / n;
  const inner = Math.max(barW * 0.72, 0.5);
  const pad = (barW - inner) / 2;

  const bars = data.map((v, i) => {
    const bh = (v / max) * (H - 1);
    const x = i * barW + pad;
    const y = H - bh;
    return `<rect class="spark-bar" x="${x.toFixed(2)}" y="${y.toFixed(2)}" ` +
      `width="${inner.toFixed(2)}" height="${Math.max(bh, 0.5).toFixed(2)}"/>`;
  }).join("");

  const peak = data.reduce((m, v) => Math.max(m, v), 0);
  const label = `Queries per second over the last ${n} seconds, peak ${peak}`;
  return h("div.sparkline-wrap", {
    html: `<svg class="sparkline" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" ` +
      `role="img" aria-label="${label}">${bars}</svg>`,
  });
}

function renderStats(host, stats) {
  const counters = [
    ["Total", stats.total],
    ["Authoritative", stats.authoritative],
    ["Forwarded", stats.forwarded],
    ["Cached", stats.cached],
    ["Blocked", stats.blocked, "warn"],
    ["NXDOMAIN", stats.nxdomain],
    ["Refused", stats.refused],
    ["SERVFAIL", stats.servfail],
  ];

  const qtypes = Object.entries(stats.by_qtype || {}).sort((a, b) => b[1] - a[1]);
  const max = qtypes.reduce((m, [, v]) => Math.max(m, v), 0) || 1;

  const qpsStat = (label, val) =>
    h("div.stat.stat-sm", [h("div.label", label), h("div.value", fmtQps(val))]);

  clear(host).appendChild(
    h("div.section", [
      h("h2", { style: "margin-bottom:12px" }, "Query statistics"),

      // requests/sec card with sparkline
      h("div.card.section", [
        h("div.card-head", [h("h2", "Requests per second"), h("div.spacer"), h("span.inline-note", "live")]),
        h("div.card-pad", [
          h("div.grid.grid-cards", { style: "margin-bottom:14px" }, [
            qpsStat("Now (10s)", stats.qps_10s),
            qpsStat("Last minute", stats.qps_1m),
            qpsStat("Average", stats.qps_avg),
          ]),
          sparkline(stats.series_per_sec),
          h("div.inline-note", { style: "margin-top:6px" }, "Queries per second, last 60 seconds (oldest left)."),
        ]),
      ]),

      h("div.grid.grid-cards", { style: "margin-bottom:16px" },
        counters.map(([label, val, kind]) =>
          h(`div.stat${kind ? ".stat-" + kind : ""}`, [h("div.label", label), h("div.value", fmtInt(val))])
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

function privacyEmpty() {
  return h("div.empty", [
    h("h3", "Per-query insights are off"),
    h("p", [
      "Query logging is off (privacy). ",
      h("a", { href: "#/settings" }, "Enable in Settings"),
      " to see recent queries and top domains.",
    ]),
  ]);
}

function topTable(title, rows) {
  let body;
  if (!rows || !rows.length) {
    body = h("div.card-pad", h("div.inline-note", "No data yet."));
  } else {
    const max = rows.reduce((m, r) => Math.max(m, Number(r.count) || 0), 0) || 1;
    body = h("div.table-wrap", { style: "border:none;max-height:320px" },
      h("table.tbl", [
        h("thead", h("tr", [h("th", "Name"), h("th", { style: "text-align:right" }, "Count")])),
        h("tbody", rows.map((r) =>
          h("tr", [
            h("td.mono.wrap", [
              r.name,
              h("div.top-bar", h("span", { style: `width:${Math.round(((Number(r.count) || 0) / max) * 100)}%` })),
            ]),
            h("td.mono", { style: "text-align:right" }, fmtInt(r.count)),
          ])
        )),
      ])
    );
  }
  return h("div.card", [h("div.card-head", [h("h2", title)]), body]);
}

function renderTop(host, stats) {
  const off = stats.query_log === "off";
  clear(host).appendChild(
    h("div.section", [
      h("h2", { style: "margin-bottom:12px" }, "Top domains"),
      off
        ? h("div.card", privacyEmpty())
        : h("div.grid", { style: "grid-template-columns:repeat(auto-fit,minmax(280px,1fr))" }, [
            topTable("Top domains", stats.top_domains || []),
            topTable("Top blocked", stats.top_blocked || []),
          ]),
    ])
  );
}

function renderRecent(host, stats, refreshNow) {
  const off = stats.query_log === "off";
  const recent = stats.recent || [];

  const headChildren = [h("h2", "Recent queries"), h("div.spacer")];
  if (!off) {
    const clearBtn = h("button.btn.btn-sm", { type: "button" }, "Clear log");
    clearBtn.addEventListener("click", () => {
      confirmDialog({
        title: "Clear query log?",
        message: "This drops retained recent queries and top-domain detail. Aggregate counters are kept.",
        confirmLabel: "Clear log",
        danger: true,
        onConfirm: async () => {
          try {
            await api.clearStats();
            toast("Query log cleared.", "success");
            if (refreshNow) await refreshNow();
          } catch (err) { toastError(err); throw err; }
        },
      });
    });
    headChildren.push(clearBtn);
  }
  headChildren.push(h("span.inline-note", { style: "margin-left:10px" }, "live"));
  const head = h("div.card-head", headChildren);

  let bodyNode;
  if (off) {
    bodyNode = privacyEmpty();
  } else if (!recent.length) {
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
