// Audit log: recent mutating management actions (who, what, when, from where).

import { api } from "../api.js";
import { h, clear, loadingBlock, toastError, badge } from "../ui.js";

export async function renderAudit(root) {
  root.appendChild(loadingBlock());
  let data;
  try {
    data = await api.audit();
  } catch (e) {
    toastError(e, "Could not load the audit log.");
    return;
  }

  clear(root);
  root.appendChild(h("div.page-head", [
    h("div", [
      h("h1", "Audit log"),
      h("div.subtitle", "Recent changes made through the management API."),
    ]),
  ]));

  const entries = data.audit || [];
  if (!entries.length) {
    root.appendChild(h("div.card", h("div.card-pad", h("div.empty", [
      h("h3", "No actions recorded yet"),
      h("p", "Changes you make in the UI (create/update/delete) will appear here."),
    ]))));
    return;
  }

  const rows = entries.map((e) =>
    h("tr", [
      h("td", h("span.mono", fmtTime(e.at))),
      h("td", e.username || "?"),
      h("td", h("span.mono", e.action)),
      h("td", badge(String(e.status), e.status >= 200 && e.status < 300 ? "on" : "warn")),
      h("td", h("span.mono", e.ip || "")),
    ])
  );

  root.appendChild(h("div.card", h("div.table-wrap",
    h("table.tbl", [
      h("thead", h("tr", [
        h("th", "When"), h("th", "User"), h("th", "Action"), h("th", "Status"), h("th", "Source"),
      ])),
      h("tbody", rows),
    ])
  )));
}

function fmtTime(s) {
  if (!s) return "";
  const d = new Date(s);
  return isNaN(d) ? s : d.toLocaleString();
}
