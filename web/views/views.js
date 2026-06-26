// Views (split-horizon) list with create/edit/delete.

import { api } from "../api.js";
import {
  h, clear, icon, badge,
  loadingBlock, emptyState, openDialog, confirmDialog,
  applyFieldErrors, toast, toastError,
} from "../ui.js";

export async function renderViews(root, { navigate }) {
  root.appendChild(loadingBlock());
  const { views } = await api.listViews();
  const sorted = [...views].sort((a, b) => a.priority - b.priority);
  const reload = () => renderViews(root, { navigate });

  const add = h("button.btn.btn-primary", [icon("plus", 16), "New view"]);
  add.addEventListener("click", () => openViewDialog({ onSaved: reload }));

  const head = h("div.page-head", [
    h("div", [h("h1", "Views"),
      h("div.subtitle", "Split-horizon: the lowest-priority view whose networks match the client wins.")]),
    h("div.spacer"),
    add,
  ]);

  if (!sorted.length) {
    const b = h("button.btn.btn-primary", [icon("plus", 16), "Create a view"]);
    b.addEventListener("click", () => openViewDialog({ onSaved: reload }));
    clear(root).appendChild(h("div", [head,
      h("div.card", emptyState("views", "No views configured",
        "Define client networks to serve different records per network.", b))]));
    return;
  }

  const rows = sorted.map((v) => {
    const edit = h("button.btn-icon", { title: "Edit view", "aria-label": "Edit view" }, icon("edit", 16));
    edit.addEventListener("click", () => openViewDialog({ view: v, onSaved: reload }));

    const del = h("button.btn-icon", {
      title: v.is_default ? "The default view cannot be deleted" : "Delete view",
      "aria-label": "Delete view",
      disabled: v.is_default,
    }, icon("trash", 16));
    if (!v.is_default) {
      del.addEventListener("click", () => {
        confirmDialog({
          title: `Delete view ${v.name}?`,
          message: "Records bound to this view will fall back to their all-views entry.",
          confirmLabel: "Delete view",
          danger: true,
          onConfirm: async () => {
            try {
              await api.deleteView(v.id);
              toast(`View ${v.name} deleted.`, "success");
              reload();
            } catch (err) { toastError(err); throw err; }
          },
        });
      });
    }

    return h("tr", [
      h("td.mono", h("strong", v.name)),
      h("td", String(v.priority)),
      h("td.wrap", v.networks && v.networks.length
        ? h("div", { style: "display:flex;flex-wrap:wrap;gap:4px" },
            v.networks.map((n) => h("span.badge.badge-muted.mono", n)))
        : h("span.inline-note", "any")),
      h("td", v.is_default ? badge("default", "accent") : h("span.inline-note", "-")),
      h("td.actions", h("div", { style: "display:flex;gap:2px;justify-content:flex-end" }, [edit, del])),
    ]);
  });

  clear(root).appendChild(h("div", [
    head,
    h("div.table-wrap",
      h("table.tbl", [
        h("thead", h("tr", [
          h("th", "Name"), h("th", "Priority"), h("th", "Networks"),
          h("th", "Default"), h("th", ""),
        ])),
        h("tbody", rows),
      ])
    ),
  ]));
}

function cidrRow(value = "") {
  const input = h("input", { type: "text", value, placeholder: "192.168.0.0/16" });
  const remove = h("button.btn-icon", { type: "button", title: "Remove", "aria-label": "Remove network" }, icon("close", 16));
  const row = h("div.repeat-row", [input, remove]);
  remove.addEventListener("click", () => row.remove());
  return row;
}

function openViewDialog({ view, onSaved }) {
  const isEdit = !!view;
  const name = h("input", { type: "text", name: "name", value: view ? view.name : "", placeholder: "internal", required: true });
  const priority = h("input", { type: "number", name: "priority", value: view ? view.priority : 10, min: 0 });

  const cidrList = h("div");
  const seed = view && view.networks && view.networks.length ? view.networks : [""];
  seed.forEach((n) => cidrList.appendChild(cidrRow(n)));

  const addCidr = h("button.btn.btn-sm", { type: "button" }, [icon("plus", 16), "Add network"]);
  addCidr.addEventListener("click", () => cidrList.appendChild(cidrRow()));

  const form = h("form", [
    h("div.form-row", [
      h("div.field", [h("label", "Name"), name,
        h("div.hint", "Letters, numbers, dash, underscore. Max 40 chars.")]),
      h("div.field", { style: "max-width:140px" }, [h("label", "Priority"), priority,
        h("div.hint", "Lower wins first.")]),
    ]),
    h("div.field", [
      h("label", "Client networks (CIDR)"),
      cidrList,
      addCidr,
    ]),
    isEdit && view.is_default
      ? h("div.inline-note", { style: "margin-top:8px" }, "This is the default view and cannot be deleted.")
      : null,
  ]);

  openDialog({
    title: isEdit ? "Edit view" : "New view",
    body: form,
    actions: [
      { label: "Cancel" },
      {
        label: isEdit ? "Save changes" : "Create view",
        kind: "primary",
        onClick: async () => {
          form.querySelectorAll(".invalid").forEach((x) => x.classList.remove("invalid"));
          form.querySelectorAll(".err").forEach((x) => x.remove());
          if (!name.value.trim()) { name.classList.add("invalid"); return false; }

          const networks = [...cidrList.querySelectorAll("input")]
            .map((i) => i.value.trim())
            .filter(Boolean);

          const body = {
            name: name.value.trim(),
            priority: Number(priority.value),
            networks,
          };
          try {
            if (isEdit) {
              await api.updateView(view.id, body);
              toast("View updated.", "success");
            } else {
              await api.createView(body);
              toast("View created.", "success");
            }
            onSaved();
          } catch (err) {
            if (err.status === 422 && applyFieldErrors(form, err)) return false;
            if (err.status === 409) { name.classList.add("invalid"); toast(err.message || "A view with that name already exists.", "error"); return false; }
            toastError(err);
            return false;
          }
        },
      },
    ],
  });
}
