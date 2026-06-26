// Request log: the full persistent query log, paginated, filterable, sortable,
// with per-row quick actions (block / allow / rewrite).

import { api } from "../api.js";
import {
  h, clear, badge, icon, fmtInt, fmtClock,
  loadingBlock, emptyState, confirmDialog, toast, toastError,
} from "../ui.js";
import { queryActions } from "./query-actions.js";

const OUTCOME_KIND = {
  authoritative: "accent", cached: "muted", forwarded: "accent", rewritten: "accent",
  blocked: "warn", nxdomain: "warn", refused: "danger", servfail: "danger", dangerous: "danger",
};
const RCODE_KIND = { NOERROR: "on", NXDOMAIN: "warn", SERVFAIL: "danger", REFUSED: "danger" };
const OUTCOMES = ["", "authoritative", "forwarded", "cached", "blocked", "dangerous",
  "rewritten", "nxdomain", "refused", "servfail"];

// Sortable columns -> backend sort key.
const COLUMNS = [
  { key: "at", label: "Time", sort: "at" },
  { key: "client", label: "Client", sort: "client" },
  { key: "view", label: "View", sort: null },
  { key: "name", label: "Name", sort: "name" },
  { key: "qtype", label: "Type", sort: "qtype" },
  { key: "outcome", label: "Outcome", sort: "outcome" },
  { key: "rcode", label: "RCODE", sort: null },
];

export async function renderQueries(root, { navigate }) {
  const state = {
    page: 1, per_page: 50,
    q: "", outcome: "", qtype: "",
    sort: "at", desc: true,
  };
  // Seed filters from the URL query string (e.g. #/queries?q=foo).
  const hashQs = (location.hash.split("?")[1] || "");
  const sp = new URLSearchParams(hashQs);
  if (sp.get("q")) state.q = sp.get("q");
  if (sp.get("outcome")) state.outcome = sp.get("outcome");

  const tableHost = h("div");
  const search = h("input", { type: "search", placeholder: "Search name or client...", value: state.q, style: "min-width:220px" });
  const outcomeSel = h("select", { style: "width:170px" },
    OUTCOMES.map((o) => h("option", { value: o, selected: o === state.outcome }, o || "All outcomes")));
  const qtypeInput = h("input", { type: "text", placeholder: "Type (A, AAAA...)", value: state.qtype, style: "width:140px;text-transform:uppercase" });

  let debounce = null;
  const apply = () => {
    state.q = search.value.trim();
    state.outcome = outcomeSel.value;
    state.qtype = qtypeInput.value.trim();
    state.page = 1;
    refresh();
  };
  search.addEventListener("input", () => { clearTimeout(debounce); debounce = setTimeout(apply, 300); });
  outcomeSel.addEventListener("change", apply);
  qtypeInput.addEventListener("input", () => { clearTimeout(debounce); debounce = setTimeout(apply, 300); });

  const clearBtn = h("button.btn.btn-sm", { type: "button" }, [icon("trash", 15), "Clear log"]);
  clearBtn.addEventListener("click", () => {
    confirmDialog({
      title: "Clear the request log?",
      message: "This permanently deletes all persisted query-log rows. Aggregate counters are kept.",
      confirmLabel: "Clear log", danger: true,
      onConfirm: async () => {
        try { await api.clearQueryLog(); toast("Request log cleared.", "success"); state.page = 1; refresh(); }
        catch (err) { toastError(err); throw err; }
      },
    });
  });

  const head = h("div.page-head", [
    h("div", [h("h1", "Request log"),
      h("div.subtitle", "Every resolved query (when query logging is enabled).")]),
    h("div.spacer"),
    clearBtn,
  ]);

  const filterBar = h("div.card.card-pad", { style: "display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:14px" },
    [search, outcomeSel, qtypeInput]);

  clear(root).appendChild(h("div", [head, filterBar, tableHost]));

  async function refresh() {
    tableHost.replaceChildren(loadingBlock());
    let data;
    try {
      data = await api.queryLog({
        page: state.page, per_page: state.per_page,
        q: state.q, outcome: state.outcome, qtype: state.qtype,
        sort: state.sort, desc: state.desc,
      });
    } catch (err) { toastError(err); return; }
    renderTable(data);
  }

  function setSort(col) {
    if (!col.sort) return;
    if (state.sort === col.sort) state.desc = !state.desc;
    else { state.sort = col.sort; state.desc = true; }
    refresh();
  }

  function renderTable(data) {
    const rows = data.queries || [];
    const total = data.total || 0;
    const pages = Math.max(1, Math.ceil(total / state.per_page));

    if (!total) {
      tableHost.replaceChildren(h("div.card",
        emptyState("inbox", "No matching queries",
          state.q || state.outcome || state.qtype
            ? "Try clearing the filters."
            : "Queries appear here once clients resolve names and logging is on.")));
      return;
    }

    const ths = COLUMNS.map((c) => {
      const active = c.sort && state.sort === c.sort;
      const arrow = active ? (state.desc ? " ▼" : " ▲") : "";
      const th = h("th", { style: c.sort ? "cursor:pointer;user-select:none" : "" }, (c.label + arrow));
      if (c.sort) th.addEventListener("click", () => setSort(c));
      return th;
    });
    ths.push(h("th", { style: "text-align:right" }, "Actions"));

    const table = h("div.table-wrap",
      h("table.tbl", [
        h("thead", h("tr", ths)),
        h("tbody", rows.map((q) =>
          h("tr", [
            h("td.mono", fmtClock(q.at)),
            h("td.mono", q.client),
            h("td", q.view || h("span.inline-note", "-")),
            h("td.mono.wrap", q.name),
            h("td.mono", q.qtype),
            h("td", badge(q.outcome, OUTCOME_KIND[q.outcome] || "muted")),
            h("td", badge(q.rcode, RCODE_KIND[q.rcode] || "muted")),
            h("td.actions", queryActions(q.name, null)),
          ])
        )),
      ])
    );

    const from = (state.page - 1) * state.per_page + 1;
    const to = Math.min(total, state.page * state.per_page);
    const prev = h("button.btn.btn-sm", { type: "button", disabled: state.page <= 1 }, "← Prev");
    const next = h("button.btn.btn-sm", { type: "button", disabled: state.page >= pages }, "Next →");
    prev.addEventListener("click", () => { if (state.page > 1) { state.page--; refresh(); } });
    next.addEventListener("click", () => { if (state.page < pages) { state.page++; refresh(); } });

    const pager = h("div", { style: "display:flex;align-items:center;gap:12px;margin-top:12px" }, [
      h("span.inline-note", `${fmtInt(from)}–${fmtInt(to)} of ${fmtInt(total)}`),
      h("div.spacer"),
      prev,
      h("span.inline-note", `Page ${state.page} / ${pages}`),
      next,
    ]);

    tableHost.replaceChildren(h("div", [table, pager]));
  }

  await refresh();
}
