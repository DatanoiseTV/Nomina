// DynDNS tokens: scoped credentials that let a router / ddclient update the
// A/AAAA records of specific hostnames via the /nic/update endpoint.

import { api } from "../api.js";
import {
  h, clear, icon,
  loadingBlock, emptyState, openDialog, confirmDialog,
  applyFieldErrors, toast, toastError,
} from "../ui.js";

export async function renderDyndns(root, { navigate }) {
  root.appendChild(loadingBlock());
  const { tokens } = await api.listDyndnsTokens();
  const reload = () => renderDyndns(root, { navigate });

  const add = h("button.btn.btn-primary", [icon("plus", 16), "New token"]);
  add.addEventListener("click", () => openTokenDialog({ onSaved: reload }));

  const head = h("div.page-head", [
    h("div", [h("h1", "DynDNS"),
      h("div.subtitle", "Let routers and dynamic-IP clients update records over HTTP.")]),
    h("div.spacer"),
    add,
  ]);

  const notice = h("div.notice", [
    icon("link", 18),
    h("div", [
      "Point any DynDNS2-compatible client (ddclient, FRITZ!Box, UniFi, OpenWrt) at ",
      h("span.mono", `${location.origin}/nic/update`),
      ". Each token uses HTTP Basic auth and may only update the hostnames you assign to it. ",
      "If ", h("code", "myip"), " is omitted, the client's source address is used.",
    ]),
  ]);

  if (!tokens.length) {
    const b = h("button.btn.btn-primary", [icon("plus", 16), "Add a token"]);
    b.addEventListener("click", () => openTokenDialog({ onSaved: reload }));
    clear(root).appendChild(h("div", [head, notice,
      h("div.card", emptyState("link", "No DynDNS tokens",
        "Create a token to give a router or client permission to update a hostname.", b))]));
    return;
  }

  const rows = tokens.map((t) => row(t, reload));

  clear(root).appendChild(h("div", [
    head,
    notice,
    h("div.table-wrap",
      h("table.tbl", [
        h("thead", h("tr", [
          h("th", "Label"), h("th", "Username"), h("th", "Hostnames"),
          h("th", "TTL"), h("th", "Last update"), h("th", ""),
        ])),
        h("tbody", rows),
      ])
    ),
  ]));
}

function row(t, reload) {
  const hosts = h("td.wrap", t.hostnames.length
    ? h("div", { style: "display:flex;flex-wrap:wrap;gap:4px" },
        t.hostnames.map((hn) => h("span.badge.badge-muted.mono", hn)))
    : h("span.inline-note", "-"));

  const last = t.last_update_at
    ? h("td", [h("div.mono", new Date(t.last_update_at).toLocaleString()),
        t.last_ip ? h("div.inline-note.mono", t.last_ip) : null])
    : h("td", h("span.inline-note", "never"));

  const del = h("button.btn-icon", { title: "Delete token", "aria-label": `Delete token ${t.label}` }, icon("trash", 16));
  del.addEventListener("click", () => {
    confirmDialog({
      title: `Delete token "${t.label}"?`,
      message: "Clients using this token will no longer be able to update records.",
      confirmLabel: "Delete token",
      danger: true,
      onConfirm: async () => {
        try {
          await api.deleteDyndnsToken(t.id);
          toast(`Token "${t.label}" deleted.`, "success");
          reload();
        } catch (err) { toastError(err); throw err; }
      },
    });
  });

  return h("tr", [
    h("td", h("strong", t.label)),
    h("td.mono", t.username),
    hosts,
    h("td.mono", String(t.ttl)),
    last,
    h("td.actions", h("div", { style: "display:flex;gap:2px;justify-content:flex-end" }, [del])),
  ]);
}

function openTokenDialog({ onSaved }) {
  const label = h("input", { type: "text", name: "label", placeholder: "Home router", required: true });
  const username = h("input", { type: "text", name: "username", placeholder: "router1", required: true, autocomplete: "off" });
  const hostnames = h("textarea", { name: "hostnames", rows: 3, placeholder: "nas.home.lan\nhome.home.lan" });
  const ttl = h("input", { type: "number", name: "ttl", value: "60", min: "1" });

  const form = h("form", [
    h("div.field", [h("label", "Label"), label,
      h("div.hint", "A name to recognize this client.")]),
    h("div.field", [h("label", "Username"), username,
      h("div.hint", "The Basic-auth username the client will send.")]),
    h("div.field", [h("label", "Hostnames"), hostnames,
      h("div.hint", "One per line (or comma-separated). Each must fall inside a local zone.")]),
    h("div.field", [h("label", "Record TTL (seconds)"), ttl]),
  ]);

  openDialog({
    title: "New DynDNS token",
    body: form,
    actions: [
      { label: "Cancel" },
      {
        label: "Create token", kind: "primary",
        onClick: async () => {
          form.querySelectorAll(".invalid").forEach((x) => x.classList.remove("invalid"));
          let bad = false;
          if (!label.value.trim()) { label.classList.add("invalid"); bad = true; }
          if (!username.value.trim()) { username.classList.add("invalid"); bad = true; }
          const hosts = hostnames.value.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
          if (!hosts.length) { hostnames.classList.add("invalid"); bad = true; }
          if (bad) return false;
          try {
            const res = await api.createDyndnsToken({
              label: label.value.trim(),
              username: username.value.trim(),
              hostnames: hosts,
              ttl: parseInt(ttl.value, 10) || 60,
            });
            onSaved();
            showSecret(res);
          } catch (err) {
            if (err.status === 422 && applyFieldErrors(form, err)) return false;
            if (err.status === 409) { username.classList.add("invalid"); toast(err.message || "That username is already in use.", "error"); return false; }
            toastError(err);
            return false;
          }
        },
      },
    ],
  });
}

// One-time display of the generated credential and a ready-to-use update URL.
function showSecret(res) {
  const host = res && res.hostnames && res.hostnames[0] ? res.hostnames[0] : "<host>";
  const url = `${location.origin}/nic/update?hostname=${host}&myip=<ip>`;
  const cred = `${res.username}:${res.secret}`;

  const field = (caption, value) => {
    const input = h("input", { type: "text", value, readOnly: true, class: "mono" });
    const copy = h("button.btn-icon", { type: "button", title: "Copy" }, icon("copy", 16));
    copy.addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(value); toast("Copied.", "success"); }
      catch { input.select(); }
    });
    return h("div.field", [h("label", caption),
      h("div", { style: "display:flex;gap:6px;align-items:center" }, [input, copy])]);
  };

  openDialog({
    title: "Token created",
    body: h("div", [
      h("div.notice", [icon("shield", 18),
        h("div", "Copy the secret now — it is shown only once and cannot be retrieved later.")]),
      field("Username", res.username),
      field("Secret", res.secret),
      field("Basic auth (user:pass)", cred),
      field("Example update URL", url),
    ]),
    actions: [{ label: "Done", kind: "primary" }],
  });
}
