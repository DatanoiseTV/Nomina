// DHCP: address scopes (with full option support), static reservations, and
// live leases. Backed by /api/dhcp/*.

import { api } from "../api.js";
import {
  h, clear, icon,
  loadingBlock, emptyState, openDialog, confirmDialog,
  applyFieldErrors, toast, toastError,
} from "../ui.js";

const KINDS = ["ip", "ip_list", "u8", "u16", "u32", "bool", "text", "hex"];

export async function renderDhcp(root, { navigate }) {
  root.appendChild(loadingBlock());
  const [{ scopes }, { leases }] = await Promise.all([
    api.listDhcpScopes(),
    api.listDhcpLeases().catch(() => ({ leases: [] })),
  ]);
  const reload = () => renderDhcp(root, { navigate });

  const add = h("button.btn.btn-primary", [icon("plus", 16), "New scope"]);
  add.addEventListener("click", () => openScopeDialog({ onSaved: reload }));

  const head = h("div.page-head", [
    h("div", [h("h1", "DHCP"),
      h("div.subtitle", "Hand out addresses with full option support; optionally register leases in DNS.")]),
    h("div.spacer"),
    add,
  ]);

  const notice = h("div.notice", [
    icon("link", 18),
    h("div", [
      "The DHCP server runs only when ", h("span.mono", "[dhcp]"),
      " listen addresses are configured (ports 67 / 547 need root or CAP_NET_BIND_SERVICE). ",
      "Scopes, reservations, and options below take effect immediately.",
    ]),
  ]);

  const scopesCard = scopes.length
    ? h("div.table-wrap", h("table.tbl", [
        h("thead", h("tr", [
          h("th", "Name"), h("th", "Family"), h("th", "Subnet"), h("th", "Pool"),
          h("th", "Lease"), h("th", "DNS"), h("th", "Status"), h("th", ""),
        ])),
        h("tbody", scopes.map((s) => scopeRow(s, reload))),
      ]))
    : h("div.card", emptyState("link", "No DHCP scopes",
        "Create a scope to define a subnet, address pool, and options.",
        (() => { const b = h("button.btn.btn-primary", [icon("plus", 16), "Add a scope"]);
          b.addEventListener("click", () => openScopeDialog({ onSaved: reload })); return b; })()));

  clear(root).appendChild(h("div", [
    head, notice,
    h("div.section", [h("h2", { style: "margin-bottom:12px" }, "Scopes"), scopesCard]),
    h("div.section", [
      h("div.card-head", { style: "margin-bottom:12px" }, [h("h2", "Active leases"), h("div.spacer"),
        h("span.inline-note", `${leases.length} total`)]),
      leasesTable(leases, reload),
    ]),
  ]));
}

function fmtFamily(f) { return f === "v6" ? "IPv6" : "IPv4"; }

function scopeRow(s, reload) {
  const resv = h("button.btn-icon", { title: "Reservations", "aria-label": `Reservations for ${s.name}` }, icon("account", 16));
  resv.addEventListener("click", () => openReservationsDialog({ scope: s }));
  const edit = h("button.btn-icon", { title: "Edit scope", "aria-label": `Edit ${s.name}` }, icon("edit", 16));
  edit.addEventListener("click", () => openScopeDialog({ scope: s, onSaved: reload }));
  const del = h("button.btn-icon", { title: "Delete scope", "aria-label": `Delete ${s.name}` }, icon("trash", 16));
  del.addEventListener("click", () => confirmDialog({
    title: `Delete scope "${s.name}"?`,
    message: "Its reservations and leases are removed too.",
    confirmLabel: "Delete scope", danger: true,
    onConfirm: async () => { try { await api.deleteDhcpScope(s.id); toast("Scope deleted.", "success"); reload(); } catch (e) { toastError(e); throw e; } },
  }));

  return h("tr", [
    h("td", h("strong", s.name)),
    h("td", fmtFamily(s.family)),
    h("td.mono", s.subnet),
    h("td.mono.wrap", `${s.range_start} – ${s.range_end}`),
    h("td.mono", `${s.lease_secs}s`),
    h("td", s.dns_register ? h("span.badge.badge-accent", s.dns_zone || "on") : h("span.inline-note", "off")),
    h("td", s.enabled ? h("span.badge.badge-on", "enabled") : h("span.badge.badge-muted", "disabled")),
    h("td.actions", h("div", { style: "display:flex;gap:2px;justify-content:flex-end" }, [resv, edit, del])),
  ]);
}

function leasesTable(leases, reload) {
  if (!leases.length) {
    return h("div.card", h("div.card-pad", h("div.inline-note", "No leases yet.")));
  }
  return h("div.table-wrap", { style: "max-height:420px" }, h("table.tbl", [
    h("thead", h("tr", [
      h("th", "IP"), h("th", "Identifier (MAC/DUID)"), h("th", "Hostname"),
      h("th", "State"), h("th", "Expires"), h("th", ""),
    ])),
    h("tbody", leases.map((l) => {
      const del = h("button.btn-icon", { title: "Delete lease" }, icon("trash", 15));
      del.addEventListener("click", () => confirmDialog({
        title: `Delete lease ${l.ip}?`, message: "The address returns to the pool.",
        confirmLabel: "Delete", danger: true,
        onConfirm: async () => { try { await api.deleteDhcpLease(l.id); toast("Lease deleted.", "success"); reload(); } catch (e) { toastError(e); throw e; } },
      }));
      const kind = { active: "badge-on", offered: "badge-accent", declined: "badge-danger", released: "badge-muted", expired: "badge-muted" }[l.state] || "badge-muted";
      return h("tr", [
        h("td.mono", l.ip),
        h("td.mono.wrap", l.identifier),
        h("td", l.hostname || h("span.inline-note", "-")),
        h("td", h(`span.badge.${kind}`, l.state)),
        h("td.mono", l.expires_at ? l.expires_at.replace("T", " ").replace(/\..*/, "") : "-"),
        h("td.actions", del),
      ]);
    })),
  ]));
}

// ---- options editor -------------------------------------------------------
// Returns { el, collect() } where collect() yields a Vec<DhcpOption>.
function optionsEditor(initial, catalog) {
  const rows = h("div");
  const makeRow = (opt) => {
    const code = h("input", { type: "number", value: opt ? opt.code : "", min: 0, max: 65535, style: "width:80px", placeholder: "code" });
    const kind = h("select", { style: "width:110px" }, KINDS.map((k) => h("option", { value: k, selected: opt && opt.kind === k }, k)));
    const value = h("input", { type: "text", value: opt ? opt.value : "", placeholder: "value", style: "flex:1" });
    const rm = h("button.btn-icon.btn-icon-sm", { type: "button", title: "Remove" }, icon("trash", 15));
    const row = h("div", { style: "display:flex;gap:6px;align-items:center;margin-bottom:6px" }, [code, kind, value, rm]);
    rm.addEventListener("click", () => row.remove());
    rows.appendChild(row);
  };
  (initial || []).forEach(makeRow);

  // "Add common option" picker (prefills code + kind from the catalog).
  const picker = h("select", { style: "max-width:280px" }, [
    h("option", { value: "" }, "Add common option…"),
    ...catalog.map((d) => h("option", { value: JSON.stringify(d) }, `${d.code} — ${d.name}`)),
  ]);
  picker.addEventListener("change", () => {
    if (!picker.value) return;
    const d = JSON.parse(picker.value);
    makeRow({ code: d.code, name: d.name, value: "", kind: d.kind });
    picker.value = "";
  });
  const addCustom = h("button.btn.btn-sm", { type: "button" }, [icon("plus", 15), "Custom option"]);
  addCustom.addEventListener("click", () => makeRow({ code: "", value: "", kind: "text" }));

  const el = h("div", [
    h("div.hint", { style: "margin-bottom:6px" }, "Any option code is allowed. Common codes prefill their type."),
    rows,
    h("div", { style: "display:flex;gap:8px;align-items:center;margin-top:4px" }, [picker, addCustom]),
  ]);
  const collect = () => [...rows.children].map((row) => {
    const [code, kind, value] = row.querySelectorAll("input,select");
    return { code: parseInt(code.value, 10), kind: kind.value, value: value.value };
  }).filter((o) => Number.isInteger(o.code));
  return { el, collect };
}

// ---- scope dialog ---------------------------------------------------------
async function openScopeDialog({ scope, onSaved }) {
  const isEdit = !!scope;
  const family = isEdit ? scope.family : "v4";
  const catalog = await api.dhcpOptionCatalog(family).then((r) => r.options).catch(() => []);

  const name = h("input", { type: "text", value: scope ? scope.name : "", placeholder: "lan", required: true });
  const familySel = h("select", ["v4", "v6"].map((f) => h("option", { value: f, selected: family === f }, fmtFamily(f))));
  if (isEdit) familySel.disabled = true; // family is fixed after creation
  const subnet = h("input", { type: "text", value: scope ? scope.subnet : "", placeholder: family === "v6" ? "2001:db8::/64" : "192.168.1.0/24" });
  const rangeStart = h("input", { type: "text", value: scope ? scope.range_start : "", placeholder: "192.168.1.100" });
  const rangeEnd = h("input", { type: "text", value: scope ? scope.range_end : "", placeholder: "192.168.1.200" });
  const lease = h("input", { type: "number", value: scope ? scope.lease_secs : 86400, min: 60 });
  const serverId = h("input", { type: "text", value: scope && scope.server_id ? scope.server_id : "", placeholder: "192.168.1.1 (this server)" });
  const enabled = h("input", { type: "checkbox", checked: scope ? scope.enabled : true });
  const dnsReg = h("input", { type: "checkbox", checked: scope ? scope.dns_register : false });
  const dnsZone = h("input", { type: "text", value: scope && scope.dns_zone ? scope.dns_zone : "", placeholder: "home.lan" });

  const opts = optionsEditor(scope ? scope.options : [
    { code: 3, name: "Router", value: "", kind: "ip_list" },
    { code: 6, name: "DNS", value: "", kind: "ip_list" },
  ], catalog);

  const form = h("form", [
    h("div.form-row", [
      h("div.field", [h("label", "Name"), name]),
      h("div.field", { style: "max-width:120px" }, [h("label", "Family"), familySel]),
    ]),
    h("div.field", [h("label", "Subnet (CIDR)"), subnet]),
    h("div.form-row", [
      h("div.field", [h("label", "Pool start"), rangeStart]),
      h("div.field", [h("label", "Pool end"), rangeEnd]),
      h("div.field", { style: "max-width:140px" }, [h("label", "Lease (s)"), lease]),
    ]),
    h("div.field", [h("label", "Server identifier (IPv4)"), serverId,
      h("div.hint", "This server's address on the subnet — sent as option 54. Required for IPv4 serving.")]),
    h("div.field", [h("label.switch", [enabled, h("span.track"), h("span", "Scope enabled")])]),
    h("div.field", [h("label.switch", [dnsReg, h("span.track"), h("span", "Register leases in DNS")])]),
    h("div.field", [h("label", "DNS zone"), dnsZone,
      h("div.hint", "Zone that leased hostnames register into (when the toggle is on).")]),
    h("div.field", [h("label", "Options"), opts.el]),
  ]);

  openDialog({
    title: isEdit ? "Edit scope" : "New DHCP scope",
    width: 640,
    body: form,
    actions: [
      { label: "Cancel" },
      {
        label: isEdit ? "Save changes" : "Create scope", kind: "primary",
        onClick: async () => {
          if (!name.value.trim()) { name.classList.add("invalid"); return false; }
          const body = {
            name: name.value.trim(),
            enabled: enabled.checked,
            family: familySel.value,
            subnet: subnet.value.trim(),
            range_start: rangeStart.value.trim(),
            range_end: rangeEnd.value.trim(),
            lease_secs: parseInt(lease.value, 10) || 86400,
            dns_register: dnsReg.checked,
            dns_zone: dnsZone.value.trim() || null,
            server_id: serverId.value.trim() || null,
            options: opts.collect(),
          };
          try {
            if (isEdit) { await api.updateDhcpScope(scope.id, body); toast("Scope updated.", "success"); }
            else { await api.createDhcpScope(body); toast("Scope created.", "success"); }
            onSaved();
          } catch (err) {
            if (err.status === 422 && applyFieldErrors(form, err)) return false;
            toastError(err); return false;
          }
        },
      },
    ],
  });
}

// ---- reservations dialog --------------------------------------------------
async function openReservationsDialog({ scope }) {
  const catalog = await api.dhcpOptionCatalog(scope.family).then((r) => r.options).catch(() => []);
  const { reservations } = await api.getDhcpScope(scope.id);

  const list = h("div");
  const render = (items) => {
    clear(list);
    if (!items.length) { list.appendChild(h("div.inline-note", "No reservations.")); return; }
    items.forEach((r) => {
      const del = h("button.btn-icon.btn-icon-sm", { type: "button", title: "Delete" }, icon("trash", 15));
      del.addEventListener("click", async () => {
        try { await api.deleteDhcpReservation(r.id); toast("Reservation deleted.", "success");
          const fresh = await api.getDhcpScope(scope.id); render(fresh.reservations); } catch (e) { toastError(e); }
      });
      list.appendChild(h("div", { style: "display:flex;gap:8px;align-items:center;padding:6px 0;border-bottom:1px solid var(--border)" }, [
        h("span.mono", { style: "flex:0 0 150px" }, r.identifier),
        h("span.mono", { style: "flex:0 0 130px" }, r.ip),
        h("span", { style: "flex:1" }, r.hostname || ""),
        del,
      ]));
    });
  };
  render(reservations);

  const ident = h("input", { type: "text", placeholder: scope.family === "v6" ? "DUID (hex)" : "aa:bb:cc:dd:ee:ff", style: "flex:0 0 170px" });
  const ip = h("input", { type: "text", placeholder: "192.168.1.50", style: "flex:0 0 140px" });
  const host = h("input", { type: "text", placeholder: "hostname (optional)", style: "flex:1" });
  const addBtn = h("button.btn.btn-sm", { type: "button" }, [icon("plus", 15), "Add"]);
  addBtn.addEventListener("click", async () => {
    if (!ident.value.trim() || !ip.value.trim()) { toast("Identifier and IP are required.", "error"); return; }
    try {
      await api.createDhcpReservation(scope.id, {
        identifier: ident.value.trim(), ip: ip.value.trim(),
        hostname: host.value.trim() || null, options: [],
      });
      ident.value = ip.value = host.value = "";
      const fresh = await api.getDhcpScope(scope.id); render(fresh.reservations);
      toast("Reservation added.", "success");
    } catch (e) { toastError(e); }
  });

  openDialog({
    title: `Reservations — ${scope.name}`,
    width: 600,
    body: h("div", [
      h("div.hint", { style: "margin-bottom:8px" }, "Fixed address assignments by MAC (IPv4) or DUID (IPv6)."),
      list,
      h("div", { style: "display:flex;gap:6px;align-items:center;margin-top:12px" }, [ident, ip, host, addBtn]),
    ]),
    actions: [{ label: "Done", kind: "primary" }],
  });
}
