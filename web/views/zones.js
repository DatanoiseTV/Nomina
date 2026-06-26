// Zones list with create and delete.

import { api } from "../api.js";
import {
  h, clear, icon, onOffBadge, fmtInt, fmtTime,
  loadingBlock, emptyState, openDialog, confirmDialog,
  applyFieldErrors, toast, toastError,
} from "../ui.js";

export async function renderZones(root, { navigate }) {
  root.appendChild(loadingBlock());
  const { zones } = await api.listZones();

  const addBtn = h("button.btn.btn-primary", [icon("plus", 16), "New zone"]);
  addBtn.addEventListener("click", () => openZoneDialog(() => renderZones(root, { navigate })));

  const head = h("div.page-head", [
    h("div", [h("h1", "Zones"), h("div.subtitle", `${fmtInt(zones.length)} zone(s)`)]),
    h("div.spacer"),
    addBtn,
  ]);

  if (!zones.length) {
    const emptyAdd = h("button.btn.btn-primary", [icon("plus", 16), "Create your first zone"]);
    emptyAdd.addEventListener("click", () => openZoneDialog(() => renderZones(root, { navigate })));
    clear(root).appendChild(h("div", [head,
      h("div.card", emptyState("zones", "No zones yet",
        "Create an authoritative zone to start serving records.", emptyAdd)),
    ]));
    return;
  }

  const rows = zones.map((z) => {
    const del = h("button.btn-icon", { title: "Delete zone", "aria-label": `Delete ${z.name}` }, icon("trash", 16));
    del.addEventListener("click", (e) => {
      e.stopPropagation();
      confirmDialog({
        title: `Delete zone ${z.name}?`,
        message: "This deletes the zone and all of its records. This cannot be undone.",
        confirmLabel: "Delete zone",
        danger: true,
        onConfirm: async () => {
          try {
            await api.deleteZone(z.id);
            toast(`Zone ${z.name} deleted.`, "success");
            renderZones(root, { navigate });
          } catch (err) { toastError(err); throw err; }
        },
      });
    });

    const tr = h("tr.row-link", [
      h("td.mono", h("strong", z.name)),
      h("td", onOffBadge(z.enabled)),
      h("td", fmtInt(z.record_count)),
      h("td.mono", String(z.default_ttl)),
      h("td", fmtTime(z.updated_at)),
      h("td.actions", del),
    ]);
    tr.addEventListener("click", () => navigate(`#/zones/${z.id}`));
    return tr;
  });

  clear(root).appendChild(h("div", [
    head,
    h("div.table-wrap",
      h("table.tbl", [
        h("thead", h("tr", [
          h("th", "Name"), h("th", "Status"), h("th", "Records"),
          h("th", "Default TTL"), h("th", "Updated"), h("th", ""),
        ])),
        h("tbody", rows),
      ])
    ),
  ]));
}

function openZoneDialog(onSaved) {
  const name = h("input", { type: "text", name: "name", placeholder: "home.lan", required: true });
  const ttl = h("input", { type: "number", name: "default_ttl", value: 300, min: 0 });

  const form = h("form", [
    h("div.field", [h("label", "Zone name"), name,
      h("div.hint", "A valid DNS name, stored without a trailing dot. A default SOA and NS record are created automatically.")]),
    h("div.field", [h("label", "Default TTL (seconds)"), ttl]),
  ]);

  openDialog({
    title: "New zone",
    body: form,
    actions: [
      { label: "Cancel" },
      {
        label: "Create zone", kind: "primary",
        onClick: async () => {
          form.querySelectorAll(".invalid").forEach((e) => e.classList.remove("invalid"));
          form.querySelectorAll(".err").forEach((e) => e.remove());
          if (!name.value.trim()) { name.classList.add("invalid"); return false; }
          const body = { name: name.value.trim() };
          if (ttl.value !== "") body.default_ttl = Number(ttl.value);
          try {
            await api.createZone(body);
            toast(`Zone ${body.name} created.`, "success");
            onSaved();
          } catch (err) {
            if (err.status === 422 && applyFieldErrors(form, err)) return false;
            toastError(err);
            return false;
          }
        },
      },
    ],
  });
}
