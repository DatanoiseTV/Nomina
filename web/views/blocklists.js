// Blocklists: subscribe to hosts/domains sources, refresh, toggle, delete.

import { api } from "../api.js";
import {
  h, clear, icon, badge, fmtInt, fmtTime,
  loadingBlock, emptyState, openDialog, confirmDialog,
  applyFieldErrors, toast, toastError,
} from "../ui.js";

const FORMATS = [
  { id: "hosts", label: "hosts (0.0.0.0 domain)" },
  { id: "domains", label: "domains (one per line)" },
];

export async function renderBlocklists(root, { navigate }) {
  root.appendChild(loadingBlock());
  const { blocklists } = await api.listBlocklists();
  const reload = () => renderBlocklists(root, { navigate });

  const add = h("button.btn.btn-primary", [icon("plus", 16), "Add source"]);
  add.addEventListener("click", () => openBlocklistDialog({ onSaved: reload }));

  const refreshAll = h("button.btn", [icon("refresh", 16), "Refresh all"]);
  if (!blocklists.length) refreshAll.disabled = true;
  refreshAll.addEventListener("click", async () => {
    refreshAll.disabled = true;
    const spin = h("span.spinner-sm", { style: "margin-right:6px" });
    clear(refreshAll).appendChild(h("span", { style: "display:inline-flex;align-items:center" }, [spin, "Refreshing..."]));
    try {
      const res = await api.refreshAllBlocklists();
      const total = (res.blocklists || []).reduce((n, b) => n + (b.entry_count || 0), 0);
      toast(`Refreshed ${(res.blocklists || []).length} source(s), ${fmtInt(total)} entries.`, "success");
      reload();
    } catch (err) {
      toastError(err);
      clear(refreshAll).appendChild(h("span", { style: "display:inline-flex;align-items:center;gap:6px" }, [icon("refresh", 16), "Refresh all"]));
      refreshAll.disabled = false;
    }
  });

  const head = h("div.page-head", [
    h("div", [h("h1", "Blocklists"),
      h("div.subtitle", "Subscribe to hosts/domains feeds. Lists are cached locally and survive restarts.")]),
    h("div.spacer"),
    refreshAll,
    add,
  ]);

  const settingsLink = h("a", { href: "#/settings" }, "Settings");
  const notice = h("div.notice", [
    icon("shield", 18),
    h("div", ["Blocklist filtering and how blocked names are answered (block mode) are configured in ", settingsLink, "."]),
  ]);

  if (!blocklists.length) {
    const b = h("button.btn.btn-primary", [icon("plus", 16), "Add a blocklist"]);
    b.addEventListener("click", () => openBlocklistDialog({ onSaved: reload }));
    clear(root).appendChild(h("div", [head, notice,
      h("div.card", emptyState("shield", "No blocklists",
        "Add a hosts or domains feed to start blocking unwanted domains.", b))]));
    return;
  }

  const rows = blocklists.map((bl) => row(bl, reload));

  clear(root).appendChild(h("div", [
    head,
    notice,
    h("div.table-wrap",
      h("table.tbl", [
        h("thead", h("tr", [
          h("th", "Name"), h("th", "Format"), h("th", "Status"),
          h("th", "Entries"), h("th", "Updated"), h("th", ""),
        ])),
        h("tbody", rows),
      ])
    ),
  ]));
}

function row(bl, reload) {
  // Enable/disable toggle
  const toggle = h("input", { type: "checkbox", checked: !!bl.enabled, "aria-label": `Enable ${bl.name}` });
  toggle.addEventListener("change", async () => {
    toggle.disabled = true;
    try {
      await api.updateBlocklist(bl.id, { enabled: toggle.checked });
      toast(`${bl.name} ${toggle.checked ? "enabled" : "disabled"}.`, "success");
      bl.enabled = toggle.checked;
    } catch (err) {
      toggle.checked = !toggle.checked;
      toastError(err);
    } finally {
      toggle.disabled = false;
    }
  });

  // Refresh one
  const refresh = h("button.btn-icon", { title: "Refresh now", "aria-label": `Refresh ${bl.name}` }, icon("refresh", 16));
  refresh.addEventListener("click", async () => {
    refresh.disabled = true;
    clear(refresh).appendChild(h("span.spinner-sm"));
    try {
      const res = await api.refreshBlocklist(bl.id);
      const updated = res.blocklist || bl;
      toast(`${bl.name} refreshed: ${fmtInt(updated.entry_count)} entries.`, "success");
      reload();
    } catch (err) {
      toastError(err);
      clear(refresh).appendChild(icon("refresh", 16));
      refresh.disabled = false;
    }
  });

  const del = h("button.btn-icon", { title: "Delete source", "aria-label": `Delete ${bl.name}` }, icon("trash", 16));
  del.addEventListener("click", () => {
    confirmDialog({
      title: `Delete blocklist ${bl.name}?`,
      message: "The cached domains for this source will be removed.",
      confirmLabel: "Delete source",
      danger: true,
      onConfirm: async () => {
        try {
          await api.deleteBlocklist(bl.id);
          toast(`Blocklist ${bl.name} deleted.`, "success");
          reload();
        } catch (err) { toastError(err); throw err; }
      },
    });
  });

  const nameCell = h("td", [
    h("strong", bl.name),
    h("div.mono", { style: "color:var(--text-muted);font-size:0.8rem;margin-top:2px;word-break:break-all" }, bl.url),
    bl.last_error
      ? h("div", { style: "margin-top:4px" }, badge(bl.last_error, "danger"))
      : null,
  ]);

  return h("tr", [
    nameCell,
    h("td.mono", bl.format),
    h("td", h("label.switch", [toggle, h("span.track")])),
    h("td", fmtInt(bl.entry_count)),
    h("td", bl.last_updated ? fmtTime(bl.last_updated) : h("span.inline-note", "never")),
    h("td.actions", h("div", { style: "display:flex;gap:2px;justify-content:flex-end" }, [refresh, del])),
  ]);
}

function openBlocklistDialog({ onSaved }) {
  const name = h("input", { type: "text", name: "name", placeholder: "StevenBlack", required: true });
  const url = h("input", { type: "url", name: "url", placeholder: "https://example.com/hosts", required: true });
  const format = h("select", { name: "format" },
    FORMATS.map((f) => h("option", { value: f.id }, f.label)));
  const refreshNow = h("input", { type: "checkbox", name: "refresh_now", checked: true });

  const form = h("form", [
    h("div.field", [h("label", "Name"), name]),
    h("div.field", [h("label", "URL"), url,
      h("div.hint", "Direct link to a hosts file or a plain domain list.")]),
    h("div.field", { style: "max-width:280px" }, [h("label", "Format"), format]),
    h("div.field", [
      h("label.switch", [refreshNow, h("span.track"), h("span", "Fetch entries now")]),
    ]),
  ]);

  openDialog({
    title: "Add blocklist",
    body: form,
    actions: [
      { label: "Cancel" },
      {
        label: "Add source", kind: "primary",
        onClick: async () => {
          form.querySelectorAll(".invalid").forEach((x) => x.classList.remove("invalid"));
          form.querySelectorAll(".err").forEach((x) => x.remove());
          let bad = false;
          if (!name.value.trim()) { name.classList.add("invalid"); bad = true; }
          if (!url.value.trim()) { url.classList.add("invalid"); bad = true; }
          if (bad) return false;
          const body = {
            name: name.value.trim(),
            url: url.value.trim(),
            format: format.value,
            refresh_now: refreshNow.checked,
          };
          try {
            const res = await api.createBlocklist(body);
            const bl = res.blocklist;
            toast(refreshNow.checked && bl
              ? `Added ${bl.name}: ${fmtInt(bl.entry_count)} entries.`
              : `Blocklist ${body.name} added.`, "success");
            onSaved();
          } catch (err) {
            if (err.status === 422 && applyFieldErrors(form, err)) return false;
            if (err.status === 409) { toast(err.message || "A blocklist with that name or URL already exists.", "error"); return false; }
            toastError(err);
            return false;
          }
        },
      },
    ],
  });
}
