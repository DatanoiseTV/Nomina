// Zone detail: editable SOA/settings + records table with CRUD.

import { api } from "../api.js";
import {
  h, clear, icon, badge, onOffBadge,
  loadingBlock, emptyState, openDialog, confirmDialog,
  applyFieldErrors, toast, toastError,
} from "../ui.js";

// Per-type structured fields. Each field becomes one input; on save the values
// are joined (in order) into the presentation-format `data` string the API
// expects, and on edit an existing `data` string is split back into fields.
// `quote` wraps/strips double quotes; `rest` absorbs all remaining tokens (for
// trailing free-form data like keys, hex, or TXT). Order matches the RFC
// presentation format and is verified by the `all_supported_types_parse` test.
const NUM = "number";
const FIELD_SCHEMAS = {
  A: [{ key: "address", label: "IPv4 address", placeholder: "203.0.113.10" }],
  AAAA: [{ key: "address", label: "IPv6 address", placeholder: "2001:db8::1" }],
  ANAME: [{ key: "target", label: "Target name", placeholder: "host.example.com." }],
  CNAME: [{ key: "target", label: "Target name", placeholder: "host.example.com.", hint: "Trailing dot = absolute; otherwise relative to the zone." }],
  NS: [{ key: "target", label: "Nameserver", placeholder: "ns1.example.com." }],
  PTR: [{ key: "target", label: "Target name", placeholder: "host.example.com.", hint: "The record name is the reversed-IP label." }],
  MX: [
    { key: "preference", type: NUM, label: "Preference", placeholder: "10", width: 120 },
    { key: "exchange", label: "Mail server", placeholder: "mail.example.com." },
  ],
  SRV: [
    { key: "priority", type: NUM, label: "Priority", placeholder: "0", width: 100 },
    { key: "weight", type: NUM, label: "Weight", placeholder: "5", width: 100 },
    { key: "port", type: NUM, label: "Port", placeholder: "5060", width: 110 },
    { key: "target", label: "Target", placeholder: "sip.example.com." },
  ],
  CAA: [
    { key: "flags", type: NUM, label: "Flags", placeholder: "0", width: 90 },
    { key: "tag", type: "select", label: "Tag", options: ["issue", "issuewild", "iodef"] },
    { key: "value", label: "Value", placeholder: "letsencrypt.org", quote: true },
  ],
  TXT: [{ key: "text", label: "Text", placeholder: "v=spf1 -all", rest: true, hint: "Free text." }],
  HINFO: [
    { key: "cpu", label: "CPU", placeholder: "Intel", quote: true },
    { key: "os", label: "OS", placeholder: "Linux", quote: true },
  ],
  SSHFP: [
    { key: "algorithm", type: NUM, label: "Algorithm", placeholder: "2", width: 120 },
    { key: "fptype", type: NUM, label: "FP type", placeholder: "1", width: 120 },
    { key: "fingerprint", label: "Fingerprint (hex)", placeholder: "123456abcdef...", rest: true },
  ],
  TLSA: [
    { key: "usage", type: NUM, label: "Usage", placeholder: "3", width: 100 },
    { key: "selector", type: NUM, label: "Selector", placeholder: "0", width: 110 },
    { key: "matching", type: NUM, label: "Matching", placeholder: "1", width: 110 },
    { key: "cert", label: "Certificate data (hex)", placeholder: "aabbccdd...", rest: true },
  ],
  SMIMEA: [
    { key: "usage", type: NUM, label: "Usage", placeholder: "3", width: 100 },
    { key: "selector", type: NUM, label: "Selector", placeholder: "0", width: 110 },
    { key: "matching", type: NUM, label: "Matching", placeholder: "1", width: 110 },
    { key: "cert", label: "Certificate data (hex)", placeholder: "aabbccdd...", rest: true },
  ],
  CERT: [
    { key: "cert_type", type: NUM, label: "Type", placeholder: "1", width: 100 },
    { key: "key_tag", type: NUM, label: "Key tag", placeholder: "12345", width: 130 },
    { key: "algorithm", type: NUM, label: "Algorithm", placeholder: "8", width: 120 },
    { key: "certificate", label: "Certificate (base64)", placeholder: "aGVsbG8=", rest: true },
  ],
  CSYNC: [
    { key: "soa_serial", type: NUM, label: "SOA serial", placeholder: "123", width: 140 },
    { key: "flags", type: NUM, label: "Flags", placeholder: "3", width: 100 },
    { key: "types", label: "Types", placeholder: "A NS AAAA", rest: true },
  ],
  NAPTR: [
    { key: "order", type: NUM, label: "Order", placeholder: "100", width: 100 },
    { key: "preference", type: NUM, label: "Preference", placeholder: "10", width: 120 },
    { key: "flags", label: "Flags", placeholder: "U", quote: true, width: 110 },
    { key: "service", label: "Service", placeholder: "E2U+sip", quote: true },
    { key: "regexp", label: "Regexp", placeholder: "!^.*$!sip:info@example.com!", quote: true },
    { key: "replacement", label: "Replacement", placeholder: "." },
  ],
  SVCB: [
    { key: "priority", type: NUM, label: "Priority", placeholder: "1", width: 100 },
    { key: "target", label: "Target", placeholder: ". or svc.example.com.", width: 200 },
    { key: "params", label: "Parameters", placeholder: 'alpn="h2,h3" port=443', rest: true },
  ],
  HTTPS: [
    { key: "priority", type: NUM, label: "Priority", placeholder: "1", width: 100 },
    { key: "target", label: "Target", placeholder: ". or svc.example.com.", width: 200 },
    { key: "params", label: "Parameters", placeholder: 'alpn="h2,h3" port=443', rest: true },
  ],
  OPENPGPKEY: [{ key: "key", label: "Public key (base64)", placeholder: "mQENB...", rest: true }],
};
// Common types first, then the rest alphabetically. SOA is managed via the
// zone settings, not as a normal record; DNSSEC records are auto-generated.
const TYPE_ORDER = [
  "A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "PTR", "CAA",
  "ANAME", "CERT", "CSYNC", "HINFO", "HTTPS", "NAPTR", "OPENPGPKEY", "SMIMEA", "SSHFP", "SVCB", "TLSA",
];

// Quote-aware tokenizer for splitting an existing data string into fields.
function tokenizeData(s) {
  return (s || "").match(/"[^"]*"|\S+/g) || [];
}

// Build the `data` presentation string from the current field inputs.
function assembleData(type, inputs) {
  const schema = FIELD_SCHEMAS[type] || [{ key: "data", rest: true }];
  const parts = [];
  for (const f of schema) {
    const raw = (inputs[f.key] ? inputs[f.key].value : "").trim();
    if (f.rest) parts.push(raw);
    else if (f.quote) parts.push(`"${raw.replace(/^"|"$/g, "")}"`);
    else parts.push(raw);
  }
  return parts.join(" ").trim();
}

// Split an existing `data` string back into per-field values for editing.
function splitData(type, data) {
  const schema = FIELD_SCHEMAS[type] || [{ key: "data", rest: true }];
  const toks = tokenizeData(data);
  const vals = {};
  let i = 0;
  for (const f of schema) {
    if (f.rest) { vals[f.key] = toks.slice(i).join(" "); i = toks.length; }
    else {
      let t = toks[i++] || "";
      if (f.quote) t = t.replace(/^"|"$/g, "");
      vals[f.key] = t;
    }
  }
  return vals;
}

export async function renderZoneDetail(root, { params, navigate }) {
  const zoneId = Number(params[0]);
  root.appendChild(loadingBlock());

  const [{ zone, records }, viewsRes] = await Promise.all([
    api.getZone(zoneId),
    api.listViews().catch(() => ({ views: [] })),
  ]);
  const views = viewsRes.views || [];

  const reload = () => renderZoneDetail(root, { params, navigate });

  const back = h("a.btn.btn-ghost.btn-sm", { href: "#/zones" }, [icon("back", 16), "Zones"]);
  const exportLink = h("a.btn.btn-sm", {
    href: api.exportZoneUrl(zone.id),
    target: "_blank",
    rel: "noopener",
    title: "Open the RFC 1035 zone file",
  }, [icon("download", 16), "Export zone file"]);

  const importBtn = h("button.btn.btn-sm", { type: "button", title: "Import a BIND zone file" },
    [icon("upload", 16), "Import zone file"]);
  importBtn.addEventListener("click", () => openImportDialog({ zone, onSaved: reload }));

  const addRec = h("button.btn.btn-primary", [icon("plus", 16), "Add record"]);
  addRec.addEventListener("click", () =>
    openRecordDialog({ zone, views, onSaved: reload }));

  clear(root).appendChild(h("div", [
    h("div.page-head", [
      h("div", [
        back,
        h("h1", { style: "margin-top:8px" }, [
          h("span.mono", zone.name), " ", onOffBadge(zone.enabled),
        ]),
      ]),
      h("div.spacer"),
      importBtn,
      exportLink,
    ]),

    // SOA / settings
    zoneSettingsCard(zone, reload),

    // DNSSEC
    dnssecCard(zone),

    // records
    h("div.card.section", [
      h("div.card-head", [
        h("h2", "Records"),
        h("div.spacer"),
        addRec,
      ]),
      records.length
        ? recordsTable(zone, records, views, reload)
        : emptyState("zones", "No records", "Add A, AAAA, CNAME and other records to this zone.",
            (() => {
              const b = h("button.btn.btn-primary", [icon("plus", 16), "Add record"]);
              b.addEventListener("click", () => openRecordDialog({ zone, views, onSaved: reload }));
              return b;
            })()),
    ]),
  ]));
}

function viewName(views, id) {
  if (id == null) return "All views";
  const v = views.find((x) => x.id === id);
  return v ? v.name : `view ${id}`;
}

function recordsTable(zone, records, views, reload) {
  const rows = records.map((r) => {
    const edit = h("button.btn-icon", { title: "Edit record", "aria-label": "Edit record" }, icon("edit", 16));
    edit.addEventListener("click", () =>
      openRecordDialog({ zone, views, record: r, onSaved: reload }));

    const del = h("button.btn-icon", { title: "Delete record", "aria-label": "Delete record" }, icon("trash", 16));
    del.addEventListener("click", () => {
      confirmDialog({
        title: "Delete record?",
        message: `Delete ${r.type} record "${r.name}" (${r.data})?`,
        confirmLabel: "Delete",
        danger: true,
        onConfirm: async () => {
          try {
            await api.deleteRecord(r.id);
            toast("Record deleted.", "success");
            reload();
          } catch (err) { toastError(err); throw err; }
        },
      });
    });

    return h("tr", [
      h("td.mono", h("strong", r.name)),
      h("td", badge(r.type, "accent")),
      h("td.mono.wrap", r.data),
      h("td.mono", r.ttl != null ? String(r.ttl) : h("span.inline-note", `${zone.default_ttl} (default)`)),
      h("td", r.view_id == null ? h("span.inline-note", "All views") : badge(viewName(views, r.view_id), "muted")),
      h("td", r.enabled ? badge("on", "on") : badge("off", "off")),
      h("td.actions", h("div", { style: "display:flex;gap:2px;justify-content:flex-end" }, [edit, del])),
    ]);
  });

  return h("div.table-wrap", { style: "border:none;border-top:1px solid var(--border)" },
    h("table.tbl", [
      h("thead", h("tr", [
        h("th", "Name"), h("th", "Type"), h("th", "Data"),
        h("th", "TTL"), h("th", "View"), h("th", "Status"), h("th", ""),
      ])),
      h("tbody", rows),
    ])
  );
}

// ---- Zone settings (SOA) editor -------------------------------------------
function zoneSettingsCard(zone, reload) {
  const soa = zone.soa || {};
  const enabled = h("input", { type: "checkbox", name: "enabled", checked: zone.enabled });
  const ttl = h("input", { type: "number", name: "default_ttl", value: zone.default_ttl, min: 0 });
  const primaryNs = h("input", { type: "text", name: "primary_ns", value: soa.primary_ns || "" });
  const adminEmail = h("input", { type: "text", name: "admin_email", value: soa.admin_email || "" });
  const refresh = h("input", { type: "number", name: "refresh", value: soa.refresh ?? 3600, min: 0 });
  const retry = h("input", { type: "number", name: "retry", value: soa.retry ?? 600, min: 0 });
  const expire = h("input", { type: "number", name: "expire", value: soa.expire ?? 604800, min: 0 });
  const minimum = h("input", { type: "number", name: "minimum", value: soa.minimum ?? 60, min: 0 });

  const save = h("button.btn.btn-primary", "Save zone settings");

  const form = h("form", [
    h("div.form-row", [
      h("div.field", [h("label", "Default TTL (seconds)"), ttl]),
      h("div.field", [h("label", "Status"),
        h("label.switch", [enabled, h("span.track"), h("span", "Zone enabled")])]),
    ]),
    h("h3", { style: "margin:8px 0 4px" }, "SOA record"),
    h("div.form-row", [
      h("div.field", [h("label", "Primary nameserver"), primaryNs,
        h("div.hint", "e.g. ns1.home.lan.")]),
      h("div.field", [h("label", "Admin email"), adminEmail,
        h("div.hint", "Dotted form, e.g. admin.home.lan.")]),
    ]),
    h("div.form-row", [
      h("div.field", [h("label", "Refresh"), refresh]),
      h("div.field", [h("label", "Retry"), retry]),
      h("div.field", [h("label", "Expire"), expire]),
      h("div.field", [h("label", "Minimum"), minimum]),
    ]),
    h("div", { style: "display:flex;justify-content:flex-end" }, save),
  ]);

  save.addEventListener("click", async (e) => {
    e.preventDefault();
    form.querySelectorAll(".invalid").forEach((x) => x.classList.remove("invalid"));
    form.querySelectorAll(".err").forEach((x) => x.remove());
    const body = {
      enabled: enabled.checked,
      default_ttl: Number(ttl.value),
      soa: {
        primary_ns: primaryNs.value.trim(),
        admin_email: adminEmail.value.trim(),
        refresh: Number(refresh.value),
        retry: Number(retry.value),
        expire: Number(expire.value),
        minimum: Number(minimum.value),
      },
    };
    save.disabled = true;
    try {
      await api.updateZone(zone.id, body);
      toast("Zone settings saved.", "success");
      reload();
    } catch (err) {
      if (!(err.status === 422 && applyFieldErrors(form, err))) toastError(err);
    } finally {
      save.disabled = false;
    }
  });

  return h("div.card.section", [
    h("div.card-head", [h("h2", "Zone settings")]),
    h("div.card-pad", form),
  ]);
}

// ---- DNSSEC ----------------------------------------------------------------
function dnssecCard(zone) {
  const body = h("div.card-pad", loadingBlock());
  const card = h("div.card.section", [
    h("div.card-head", [h("h2", "DNSSEC")]),
    body,
  ]);

  if (zone.is_secondary) {
    clear(body).appendChild(h("div.inline-note",
      "This is a secondary zone. Its records are replicated from the primary and signed there; Nomina does not sign replicated zones."));
    return card;
  }

  (async () => {
    try {
      const status = await api.getDnssec(zone.id);
      renderDnssecBody(body, zone, status);
    } catch (err) {
      clear(body).appendChild(
        h("div.inline-note", err && err.message ? err.message : "Could not load DNSSEC status."));
    }
  })();

  return card;
}

function renderDnssecBody(body, zone, status) {
  clear(body);

  if (!status.enabled) {
    const enable = h("button.btn.btn-primary", [icon("lock", 16), "Enable DNSSEC"]);
    enable.addEventListener("click", async () => {
      enable.disabled = true;
      try {
        const res = await api.enableDnssec(zone.id);
        toast("DNSSEC enabled. Publish the DS record at your parent zone to complete the chain of trust.", "success", 7000);
        renderDnssecBody(body, zone, res);
      } catch (err) {
        toastError(err);
        enable.disabled = false;
      }
    });
    body.appendChild(h("div", [
      h("p.inline-note", { style: "margin:0 0 12px" },
        "Sign this zone online with a single ECDSA P-256 key. Clients that set the DO bit then receive RRSIG, a DNSKEY at the apex, and signed NSEC denials."),
      enable,
    ]));
    return;
  }

  const disable = h("button.btn.btn-danger.btn-sm", [icon("trash", 16), "Disable DNSSEC"]);
  disable.addEventListener("click", () => {
    confirmDialog({
      title: "Disable DNSSEC?",
      message: "This deletes the signing key and stops serving signed responses. Remove the DS record from your parent zone first to avoid resolution failures.",
      confirmLabel: "Disable DNSSEC",
      danger: true,
      onConfirm: async () => {
        try {
          await api.disableDnssec(zone.id);
          toast("DNSSEC disabled.", "success");
          renderDnssecBody(body, zone, { enabled: false });
        } catch (err) { toastError(err); throw err; }
      },
    });
  });

  body.appendChild(h("div", [
    h("dl.kv", { style: "margin-bottom:14px" }, [
      h("dt", "Status"), h("dd", badge("Signed", "on")),
      h("dt", "Algorithm"), h("dd", h("span.mono", status.algorithm || "-")),
      h("dt", "Key tag"), h("dd", h("span.mono", status.key_tag != null ? String(status.key_tag) : "-")),
    ]),
    h("div.notice", [
      icon("shield", 18),
      h("div", "Publish the DS record at your parent zone / registrar to complete the chain of trust."),
    ]),
    keyField("DS record", status.ds),
    keyField("DNSKEY record", status.dnskey),
    h("div", { style: "display:flex;justify-content:flex-end;margin-top:8px" }, disable),
  ]));
}

function keyField(label, value) {
  if (!value) return null;
  const copy = h("button.btn-icon", { type: "button", title: `Copy ${label}`, "aria-label": `Copy ${label}` }, icon("copy", 16));
  copy.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(value);
      toast(`${label} copied to clipboard.`, "success");
    } catch (_) {
      toast("Could not copy to clipboard.", "error");
    }
  });
  return h("div.field", [
    h("label", { style: "display:flex;align-items:center;gap:8px" }, [label, copy]),
    h("code.mono", {
      style: "display:block;white-space:pre-wrap;word-break:break-all;background:var(--bg-sunken);border:1px solid var(--border);border-radius:var(--radius-sm);padding:10px 12px;font-size:0.82rem",
    }, value),
  ]);
}

// ---- Record create/edit dialog --------------------------------------------
function openRecordDialog({ zone, views, record, onSaved }) {
  const isEdit = !!record;

  const name = h("input", { type: "text", name: "name", value: record ? record.name : "", placeholder: "@ or subdomain", required: true });

  const typeSel = h("select", { name: "type" },
    TYPE_ORDER.map((t) =>
      h("option", { value: t, selected: record ? record.type === t : t === "A" }, t)
    )
  );

  const ttl = h("input", { type: "number", name: "ttl", value: record && record.ttl != null ? record.ttl : "", min: 0,
    placeholder: `default (${zone.default_ttl})` });

  const viewSel = h("select", { name: "view_id" }, [
    h("option", { value: "", selected: !record || record.view_id == null }, "All views (default)"),
    ...views.map((v) =>
      h("option", { value: String(v.id), selected: record && record.view_id === v.id },
        `${v.name}${v.is_default ? " (default)" : ""}`)
    ),
  ]);

  const enabled = h("input", { type: "checkbox", name: "enabled", checked: record ? record.enabled : true });

  // Structured, per-type data fields. Re-rendered when the type changes; the
  // current input elements are tracked in `fieldInputs` for assembly on save.
  const fieldsHost = h("div");
  const dataErr = h("div.err", { style: "display:none" });
  let fieldInputs = {};

  function renderFields(type, values) {
    clear(fieldsHost);
    fieldInputs = {};
    const schema = FIELD_SCHEMAS[type] || [{ key: "data", label: "Data", rest: true }];
    const fieldEls = schema.map((f) => {
      let input;
      if (f.type === "select") {
        input = h("select", { name: f.key },
          f.options.map((o) => h("option", { value: o, selected: (values[f.key] || f.options[0]) === o }, o)));
      } else {
        input = h("input", {
          type: f.type === "number" ? "number" : "text",
          name: f.key, value: values[f.key] || "", placeholder: f.placeholder || "",
        });
      }
      fieldInputs[f.key] = input;
      const el = h("div.field", [h("label", f.label), input, f.hint ? h("div.hint", f.hint) : null]);
      el.style.flex = f.rest ? "1 1 100%" : (f.width ? `0 0 ${f.width}px` : "1 1 160px");
      return el;
    });
    fieldsHost.appendChild(h("div", { style: "display:flex;gap:10px;flex-wrap:wrap" }, fieldEls));
  }

  // Seed from the existing record (split its data string), else empty.
  const initialType = record ? record.type : "A";
  renderFields(initialType, record ? splitData(record.type, record.data) : {});
  typeSel.addEventListener("change", () => renderFields(typeSel.value, {}));

  const form = h("form", [
    h("div.form-row", [
      h("div.field", [h("label", "Name"), name,
        h("div.hint", 'Use "@" for the zone apex. Relative to the zone.')]),
      h("div.field", { style: "max-width:130px" }, [h("label", "Type"), typeSel]),
    ]),
    h("div.field", [h("label", "Data"), fieldsHost, dataErr]),
    h("div.form-row", [
      h("div.field", [h("label", "TTL (seconds)"), ttl]),
      h("div.field", [h("label", "View"), viewSel]),
    ]),
    h("div.field", [
      h("label.switch", [enabled, h("span.track"), h("span", "Record enabled")]),
    ]),
  ]);

  openDialog({
    title: isEdit ? "Edit record" : "Add record",
    body: form,
    actions: [
      { label: "Cancel" },
      {
        label: isEdit ? "Save changes" : "Add record",
        kind: "primary",
        onClick: async () => {
          form.querySelectorAll(".invalid").forEach((x) => x.classList.remove("invalid"));
          dataErr.style.display = "none";
          if (!name.value.trim()) { name.classList.add("invalid"); return false; }

          // Every structured field is required (the trailing free-form field too).
          let missing = false;
          for (const inp of Object.values(fieldInputs)) {
            if (!String(inp.value).trim()) { inp.classList.add("invalid"); missing = true; }
          }
          if (missing) { dataErr.textContent = "Fill in all data fields."; dataErr.style.display = ""; return false; }

          const body = {
            name: name.value.trim(),
            type: typeSel.value,
            data: assembleData(typeSel.value, fieldInputs),
            view_id: viewSel.value === "" ? null : Number(viewSel.value),
            enabled: enabled.checked,
          };
          body.ttl = ttl.value === "" ? null : Number(ttl.value);

          try {
            if (isEdit) {
              await api.updateRecord(record.id, body);
              toast("Record updated.", "success");
            } else {
              await api.createRecord(zone.id, body);
              toast("Record added.", "success");
            }
            onSaved();
          } catch (err) {
            // Server validates the assembled data string; surface its message
            // (and the name error) inline rather than against a single field.
            if (err.status === 422 && err.fields) {
              if (err.fields.name) { name.classList.add("invalid"); }
              if (err.fields.data) { dataErr.textContent = err.fields.data; dataErr.style.display = ""; }
              if (err.fields.name || err.fields.data) return false;
            }
            toastError(err);
            return false;
          }
        },
      },
    ],
  });
}

// ---- Zone import dialog ----------------------------------------------------
function openImportDialog({ zone, onSaved }) {
  const zonefile = h("textarea", {
    name: "zonefile",
    rows: 16,
    spellcheck: "false",
    placeholder: "$ORIGIN home.lan.\n$TTL 300\n@   IN  A   10.0.0.1\nnas IN  A   10.0.0.5",
    style: "font-family:var(--font-mono);width:100%",
    required: true,
  });
  const replace = h("input", { type: "checkbox", name: "replace" });

  const form = h("form", [
    h("div.field", [
      h("label", "Zone file"),
      zonefile,
      h("div.hint", "Paste a BIND-style master file. SOA and unsupported record types are skipped; records are added to the all-views set."),
    ]),
    h("div.field", [
      h("label.switch", [replace, h("span.track"), h("span", "Replace existing records")]),
      h("div.hint", "Clears this zone's existing records before importing."),
    ]),
  ]);

  openDialog({
    title: `Import into ${zone.name}`,
    body: form,
    width: "640px",
    actions: [
      { label: "Cancel" },
      {
        label: "Import",
        kind: "primary",
        onClick: async () => {
          form.querySelectorAll(".invalid").forEach((x) => x.classList.remove("invalid"));
          form.querySelectorAll(".err").forEach((x) => x.remove());
          if (!zonefile.value.trim()) { zonefile.classList.add("invalid"); return false; }
          try {
            const res = await api.importZone(zone.id, zonefile.value, replace.checked);
            toast(`Imported ${res.imported} records (${res.skipped} skipped).`, "success");
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
