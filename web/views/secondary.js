// Secondary (slave) zones: replicate a zone from a primary via AXFR and refresh
// when the primary's SOA serial changes.

import { api } from "../api.js";
import {
  h, clear, icon, badge, fmtInt, fmtTime,
  loadingBlock, emptyState, openDialog, confirmDialog,
  applyFieldErrors, toast, toastError,
} from "../ui.js";

export async function renderSecondary(root, { navigate }) {
  root.appendChild(loadingBlock());
  const { secondary_zones } = await api.listSecondaries();
  const reload = () => renderSecondary(root, { navigate });

  const add = h("button.btn.btn-primary", [icon("plus", 16), "Add secondary zone"]);
  add.addEventListener("click", () => openSecondaryDialog({ onSaved: reload }));

  const head = h("div.page-head", [
    h("div", [h("h1", "Secondary zones"),
      h("div.subtitle", `${fmtInt(secondary_zones.length)} secondary zone(s)`)]),
    h("div.spacer"),
    add,
  ]);

  const notice = h("div.notice", [
    icon("link", 18),
    h("div", "A secondary replicates a zone from a primary via AXFR and refreshes when the primary's SOA serial changes. The primary must allow AXFR from this server's IP."),
  ]);

  if (!secondary_zones.length) {
    const b = h("button.btn.btn-primary", [icon("plus", 16), "Add a secondary zone"]);
    b.addEventListener("click", () => openSecondaryDialog({ onSaved: reload }));
    clear(root).appendChild(h("div", [head, notice,
      h("div.card", emptyState("link", "No secondary zones",
        "Replicate a zone from a primary nameserver via AXFR.", b))]));
    return;
  }

  const rows = secondary_zones.map((z) => row(z, reload));

  clear(root).appendChild(h("div", [
    head,
    notice,
    h("div.table-wrap",
      h("table.tbl", [
        h("thead", h("tr", [
          h("th", "Name"), h("th", "Primary"), h("th", "Serial"),
          h("th", "Records"), h("th", "Last check"), h("th", "Status"), h("th", ""),
        ])),
        h("tbody", rows),
      ])
    ),
  ]));
}

function row(z, reload) {
  const refresh = h("button.btn-icon", { type: "button", title: "Refresh now", "aria-label": `Refresh ${z.name} now` }, icon("refresh", 16));
  refresh.addEventListener("click", async () => {
    refresh.disabled = true;
    try {
      await api.refreshSecondary(z.zone_id);
      toast(`Transfer for ${z.name} completed.`, "success");
      reload();
    } catch (err) {
      // 502 transfer_failed: the primary refused the transfer.
      toastError(err);
      refresh.disabled = false;
    }
  });

  const del = h("button.btn-icon", { type: "button", title: "Delete secondary", "aria-label": `Delete ${z.name}` }, icon("trash", 16));
  del.addEventListener("click", () => {
    confirmDialog({
      title: `Delete secondary ${z.name}?`,
      message: "This removes the replicated zone and all of its records. This cannot be undone.",
      confirmLabel: "Delete secondary",
      danger: true,
      onConfirm: async () => {
        try {
          await api.deleteZone(z.zone_id);
          toast(`Secondary ${z.name} deleted.`, "success");
          reload();
        } catch (err) { toastError(err); throw err; }
      },
    });
  });

  const status = z.last_error
    ? h("span.badge.badge-danger", { title: z.last_error }, "Error")
    : badge("OK", "on");

  return h("tr", [
    h("td.mono", h("strong", z.name)),
    h("td.mono", z.primary_addr || "-"),
    h("td.mono", z.serial != null ? String(z.serial) : "-"),
    h("td", fmtInt(z.record_count)),
    h("td", fmtTime(z.last_check)),
    h("td", z.last_error
      ? h("div", { style: "display:flex;flex-direction:column;gap:4px" }, [
          status,
          h("div", { style: "color:var(--danger);font-size:0.82rem;max-width:280px" }, z.last_error),
        ])
      : status),
    h("td.actions", h("div", { style: "display:flex;gap:2px;justify-content:flex-end" }, [refresh, del])),
  ]);
}

function openSecondaryDialog({ onSaved }) {
  const name = h("input", { type: "text", name: "name", placeholder: "home.lan", required: true });
  const primary = h("input", { type: "text", name: "primary", placeholder: "10.0.0.1 or 10.0.0.1:53", required: true });

  const form = h("form", [
    h("div.field", [h("label", "Zone name"), name,
      h("div.hint", "A valid DNS name, stored without a trailing dot. Must match the zone served by the primary.")]),
    h("div.field", [h("label", "Primary"), primary,
      h("div.hint", "The primary's address as ip or ip:port (defaults to port 53). It must allow AXFR from this server's IP.")]),
  ]);

  openDialog({
    title: "Add secondary zone",
    body: form,
    actions: [
      { label: "Cancel" },
      {
        label: "Add secondary", kind: "primary",
        onClick: async () => {
          form.querySelectorAll(".invalid").forEach((x) => x.classList.remove("invalid"));
          form.querySelectorAll(".err").forEach((x) => x.remove());
          let bad = false;
          if (!name.value.trim()) { name.classList.add("invalid"); bad = true; }
          if (!primary.value.trim()) { primary.classList.add("invalid"); bad = true; }
          if (bad) return false;

          const nm = name.value.trim();
          try {
            await api.createSecondary(nm, primary.value.trim());
            toast(`Secondary ${nm} created and transferred.`, "success");
            onSaved();
          } catch (err) {
            if (err.status === 422 && applyFieldErrors(form, err)) return false;
            if (err.status === 502) {
              toast(err.message || "The primary refused the zone transfer (AXFR). Check that it allows transfers from this server.", "error", 7000);
              return false;
            }
            if (err.status === 409) {
              name.classList.add("invalid");
              toast(err.message || "A zone with that name already exists.", "error");
              return false;
            }
            toastError(err);
            return false;
          }
        },
      },
    ],
  });
}
