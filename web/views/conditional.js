// Conditional forwarding: per-domain upstream resolvers that take precedence
// over the global resolver (and work in authoritative-only mode).

import { api } from "../api.js";
import {
  h, clear, icon, badge,
  loadingBlock, emptyState, openDialog, confirmDialog,
  applyFieldErrors, toast, toastError,
} from "../ui.js";

const PROTOCOLS = ["udp", "tcp", "tls", "https"];
const DEFAULT_PORTS = { udp: 53, tcp: 53, tls: 853, https: 443 };

export async function renderConditional(root, { navigate }) {
  root.appendChild(loadingBlock());
  const { conditional_forwards } = await api.listConditionalForwards();
  const reload = () => renderConditional(root, { navigate });

  const add = h("button.btn.btn-primary", [icon("plus", 16), "New rule"]);
  add.addEventListener("click", () => openRuleDialog({ onSaved: reload }));

  const head = h("div.page-head", [
    h("div", [h("h1", "Conditional forwarding"),
      h("div.subtitle", "Send a domain's queries to dedicated upstream resolvers.")]),
    h("div.spacer"),
    add,
  ]);

  const notice = h("div.notice", [
    icon("shuffle", 18),
    h("div", "Queries for this domain and its subdomains are sent to these resolvers instead of the global upstream — and work even in authoritative-only mode. Useful for split-DNS (e.g. corp.internal -> 10.0.0.1) or service discovery (consul -> 127.0.0.1:8600)."),
  ]);

  if (!conditional_forwards.length) {
    const b = h("button.btn.btn-primary", [icon("plus", 16), "Add a rule"]);
    b.addEventListener("click", () => openRuleDialog({ onSaved: reload }));
    clear(root).appendChild(h("div", [head, notice,
      h("div.card", emptyState("shuffle", "No conditional forwarders",
        "Route a domain to dedicated resolvers of your choice.", b))]));
    return;
  }

  const rows = conditional_forwards.map((cf) => row(cf, reload));

  clear(root).appendChild(h("div", [
    head,
    notice,
    h("div.table-wrap",
      h("table.tbl", [
        h("thead", h("tr", [
          h("th", "Domain"), h("th", "Forwarders"), h("th", "Status"), h("th", ""),
        ])),
        h("tbody", rows),
      ])
    ),
  ]));
}

function forwarderChips(forwarders) {
  if (!forwarders || !forwarders.length) return h("span.inline-note", "-");
  return h("div", { style: "display:flex;flex-wrap:wrap;gap:6px" },
    forwarders.map((f) =>
      badge(`${f.addr}:${f.port ?? DEFAULT_PORTS[f.protocol] ?? ""}/${f.protocol}`, "muted")
    )
  );
}

function row(cf, reload) {
  const toggle = h("input", { type: "checkbox", checked: !!cf.enabled, "aria-label": `Enable conditional forward for ${cf.domain}` });
  toggle.addEventListener("change", async () => {
    toggle.disabled = true;
    try {
      await api.updateConditionalForward(cf.id, { enabled: toggle.checked });
      toast(`Conditional forward for ${cf.domain} ${toggle.checked ? "enabled" : "disabled"}.`, "success");
      cf.enabled = toggle.checked;
    } catch (err) {
      toggle.checked = !toggle.checked;
      toastError(err);
    } finally {
      toggle.disabled = false;
    }
  });

  const edit = h("button.btn-icon", { title: "Edit rule", "aria-label": `Edit conditional forward for ${cf.domain}` }, icon("edit", 16));
  edit.addEventListener("click", () => openRuleDialog({ rule: cf, onSaved: reload }));

  const del = h("button.btn-icon", { title: "Delete rule", "aria-label": `Delete conditional forward for ${cf.domain}` }, icon("trash", 16));
  del.addEventListener("click", () => {
    confirmDialog({
      title: `Delete conditional forward for ${cf.domain}?`,
      message: "Queries for this domain will use the global resolver again.",
      confirmLabel: "Delete rule",
      danger: true,
      onConfirm: async () => {
        try {
          await api.deleteConditionalForward(cf.id);
          toast(`Conditional forward for ${cf.domain} deleted.`, "success");
          reload();
        } catch (err) { toastError(err); throw err; }
      },
    });
  });

  return h("tr", [
    h("td.mono", h("strong", cf.domain)),
    h("td", forwarderChips(cf.forwarders)),
    h("td", h("label.switch", [toggle, h("span.track")])),
    h("td.actions", h("div", { style: "display:flex;gap:2px;justify-content:flex-end" }, [edit, del])),
  ]);
}

function openRuleDialog({ rule, onSaved }) {
  const isEdit = !!rule;

  const domain = h("input", { type: "text", name: "domain", value: rule ? rule.domain : "", placeholder: "corp.internal", required: true });

  const forwardersHost = h("div");
  function addForwarder(f = { addr: "", protocol: "udp", port: 53, tls_name: null }) {
    forwardersHost.appendChild(forwarderRow(f));
  }
  const seed = rule && rule.forwarders && rule.forwarders.length ? rule.forwarders : [];
  seed.forEach((f) => addForwarder(f));
  if (!forwardersHost.children.length) addForwarder();

  const addBtn = h("button.btn.btn-sm", { type: "button" }, [icon("plus", 16), "Add forwarder"]);
  addBtn.addEventListener("click", () => addForwarder());

  const form = h("form", [
    isEdit ? null : h("div.field", [h("label", "Domain"), domain,
      h("div.hint", "Matches this domain and every subdomain of it.")]),
    h("div.field", [
      h("label", "Forwarders"),
      h("div.inline-note", { style: "margin-bottom:8px" },
        "tls and https protocols require a TLS server name."),
      forwardersHost,
      addBtn,
    ]),
  ]);

  openDialog({
    title: isEdit ? `Edit ${rule.domain}` : "New conditional forward",
    body: form,
    width: "560px",
    actions: [
      { label: "Cancel" },
      {
        label: isEdit ? "Save changes" : "Create rule", kind: "primary",
        onClick: async () => {
          form.querySelectorAll(".invalid").forEach((x) => x.classList.remove("invalid"));
          form.querySelectorAll(".err").forEach((x) => x.remove());

          if (!isEdit && !domain.value.trim()) { domain.classList.add("invalid"); return false; }

          const forwarders = [];
          let badRow = false;
          forwardersHost.querySelectorAll("[data-forwarder]").forEach((r) => {
            const addr = r.querySelector('[data-k="addr"]');
            const proto = r.querySelector('[data-k="protocol"]');
            const port = r.querySelector('[data-k="port"]');
            const tls = r.querySelector('[data-k="tls_name"]');
            const addrVal = addr.value.trim();
            if (!addrVal) return; // skip empty rows
            const protocol = proto.value;
            const tlsVal = tls.value.trim();
            if ((protocol === "tls" || protocol === "https") && !tlsVal) {
              tls.classList.add("invalid");
              badRow = true;
            }
            forwarders.push({
              addr: addrVal,
              protocol,
              port: port.value === "" ? DEFAULT_PORTS[protocol] : Number(port.value),
              tls_name: tlsVal || null,
            });
          });

          if (badRow) { toast("tls/https forwarders require a TLS server name.", "error"); return false; }
          if (!forwarders.length) { toast("Add at least one forwarder.", "error"); return false; }

          const dom = domain.value.trim();
          try {
            if (isEdit) {
              await api.updateConditionalForward(rule.id, { forwarders });
              toast(`Conditional forward for ${rule.domain} updated.`, "success");
            } else {
              await api.createConditionalForward({ domain: dom, forwarders });
              toast(`Conditional forward for ${dom} created.`, "success");
            }
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

function forwarderRow(f) {
  const addr = h("input", { type: "text", value: f.addr || "", placeholder: "10.0.0.1", dataset: { k: "addr" } });
  const proto = h("select", { dataset: { k: "protocol" } },
    PROTOCOLS.map((p) => h("option", { value: p, selected: f.protocol === p }, p)));
  const port = h("input", { type: "number", value: f.port ?? "", placeholder: "53", min: 1, max: 65535, dataset: { k: "port" } });
  const tls = h("input", { type: "text", value: f.tls_name || "", placeholder: "tls server name", dataset: { k: "tls_name" } });
  const remove = h("button.btn-icon", { type: "button", title: "Remove forwarder", "aria-label": "Remove forwarder" }, icon("close", 16));

  const row = h("div.repeat-row", { dataset: { forwarder: "1" }, style: "align-items:center" }, [
    h("div", { style: "flex:2" }, addr),
    h("div", { style: "flex:1;min-width:90px" }, proto),
    h("div", { style: "flex:0 0 90px" }, port),
    h("div", { style: "flex:2" }, tls),
    remove,
  ]);

  function syncTls() {
    const needs = proto.value === "tls" || proto.value === "https";
    tls.disabled = !needs;
    tls.placeholder = needs ? "tls server name (required)" : "n/a";
    if (!needs) tls.classList.remove("invalid");
  }
  proto.addEventListener("change", syncTls);
  syncTls();

  remove.addEventListener("click", () => row.remove());
  return row;
}
