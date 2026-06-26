// Manual filter rules: allow / deny a domain (and its subdomains).

import { api } from "../api.js";
import {
  h, clear, icon, badge,
  loadingBlock, emptyState, openDialog, confirmDialog,
  applyFieldErrors, toast, toastError,
} from "../ui.js";

const ACTIONS = [
  { id: "deny", label: "Deny (block)" },
  { id: "allow", label: "Allow (exempt from blocklists)" },
];

const ACTION_KIND = { deny: "danger", allow: "on" };

export async function renderRules(root, { navigate }) {
  root.appendChild(loadingBlock());
  const { rules } = await api.listRules();
  const reload = () => renderRules(root, { navigate });

  const add = h("button.btn.btn-primary", [icon("plus", 16), "New rule"]);
  add.addEventListener("click", () => openRuleDialog({ onSaved: reload }));

  const head = h("div.page-head", [
    h("div", [h("h1", "Rules"),
      h("div.subtitle", "Manual allow/deny entries. A rule matches the domain and all of its subdomains.")]),
    h("div.spacer"),
    add,
  ]);

  const notice = h("div.notice", [
    icon("filter", 18),
    h("div", "Deny blocks a domain outright. Allow exempts a domain from the blocklists (it overrides a blocklist hit)."),
  ]);

  if (!rules.length) {
    const b = h("button.btn.btn-primary", [icon("plus", 16), "Add a rule"]);
    b.addEventListener("click", () => openRuleDialog({ onSaved: reload }));
    clear(root).appendChild(h("div", [head, notice,
      h("div.card", emptyState("filter", "No rules",
        "Add a manual allow or deny rule to fine-tune filtering.", b))]));
    return;
  }

  const rows = rules.map((r) => {
    const del = h("button.btn-icon", { title: "Delete rule", "aria-label": `Delete rule for ${r.domain}` }, icon("trash", 16));
    del.addEventListener("click", () => {
      confirmDialog({
        title: `Delete rule for ${r.domain}?`,
        message: "This removes the manual rule. Blocklists and rewrites are unaffected.",
        confirmLabel: "Delete rule",
        danger: true,
        onConfirm: async () => {
          try {
            await api.deleteRule(r.id);
            toast(`Rule for ${r.domain} deleted.`, "success");
            reload();
          } catch (err) { toastError(err); throw err; }
        },
      });
    });

    return h("tr", [
      h("td.mono", h("strong", r.domain)),
      h("td", badge(r.action, ACTION_KIND[r.action] || "muted")),
      h("td.wrap", r.comment ? r.comment : h("span.inline-note", "-")),
      h("td.actions", del),
    ]);
  });

  clear(root).appendChild(h("div", [
    head,
    notice,
    h("div.table-wrap",
      h("table.tbl", [
        h("thead", h("tr", [
          h("th", "Domain"), h("th", "Action"), h("th", "Comment"), h("th", ""),
        ])),
        h("tbody", rows),
      ])
    ),
  ]));
}

function openRuleDialog({ onSaved }) {
  const domain = h("input", { type: "text", name: "domain", placeholder: "ads.example.com", required: true });
  const action = h("select", { name: "action" },
    ACTIONS.map((a) => h("option", { value: a.id }, a.label)));
  const comment = h("input", { type: "text", name: "comment", placeholder: "optional note" });

  const form = h("form", [
    h("div.field", [h("label", "Domain"), domain,
      h("div.hint", "Matches this domain and every subdomain of it.")]),
    h("div.field", { style: "max-width:320px" }, [h("label", "Action"), action]),
    h("div.field", [h("label", "Comment"), comment]),
  ]);

  openDialog({
    title: "New rule",
    body: form,
    actions: [
      { label: "Cancel" },
      {
        label: "Create rule", kind: "primary",
        onClick: async () => {
          form.querySelectorAll(".invalid").forEach((x) => x.classList.remove("invalid"));
          form.querySelectorAll(".err").forEach((x) => x.remove());
          if (!domain.value.trim()) { domain.classList.add("invalid"); return false; }
          const body = {
            domain: domain.value.trim(),
            action: action.value,
            comment: comment.value.trim() || null,
          };
          try {
            await api.createRule(body);
            toast(`Rule for ${body.domain} created.`, "success");
            onSaved();
          } catch (err) {
            if (err.status === 422 && applyFieldErrors(form, err)) return false;
            if (err.status === 409) { domain.classList.add("invalid"); toast(err.message || "A rule for that domain already exists.", "error"); return false; }
            toastError(err);
            return false;
          }
        },
      },
    ],
  });
}
