// Zone detail: editable SOA/settings + records table with CRUD.

import { api } from "../api.js";
import {
  h, clear, icon, badge, onOffBadge,
  loadingBlock, emptyState, openDialog, confirmDialog,
  applyFieldErrors, toast, toastError,
} from "../ui.js";

// Record type -> data field hint and placeholder (per API contract table).
const RECORD_TYPES = {
  A:     { placeholder: "10.0.0.5", hint: "IPv4 address." },
  AAAA:  { placeholder: "fd00::5", hint: "IPv6 address." },
  CNAME: { placeholder: "host.home.lan.", hint: "Canonical target name (use a trailing dot for FQDN)." },
  MX:    { placeholder: "10 mail.home.lan.", hint: "Format: <preference> <exchange>." },
  TXT:   { placeholder: "v=spf1 -all", hint: "Free text; quotes optional." },
  NS:    { placeholder: "ns1.home.lan.", hint: "Nameserver name." },
  SRV:   { placeholder: "0 5 5060 sip.home.lan.", hint: "Format: <priority> <weight> <port> <target>." },
  PTR:   { placeholder: "nas.home.lan.", hint: "Target name; the record name is the reversed-IP label." },
  CAA:   { placeholder: '0 issue "letsencrypt.org"', hint: 'Format: <flags> <tag> <value>.' },
};
// SOA is managed via the zone settings, not as a normal record.
const TYPE_ORDER = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SRV", "PTR", "CAA"];

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
      "This is a secondary zone. Its records are replicated from the primary and signed there; PicoNS does not sign replicated zones."));
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

  const data = h("input", { type: "text", name: "data", value: record ? record.data : "", required: true });
  const dataHint = h("div.hint");

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

  function syncTypeHints() {
    const meta = RECORD_TYPES[typeSel.value] || {};
    data.placeholder = meta.placeholder || "";
    dataHint.textContent = meta.hint || "";
  }
  typeSel.addEventListener("change", syncTypeHints);
  syncTypeHints();

  const form = h("form", [
    h("div.form-row", [
      h("div.field", [h("label", "Name"), name,
        h("div.hint", 'Use "@" for the zone apex. Relative to the zone.')]),
      h("div.field", { style: "max-width:130px" }, [h("label", "Type"), typeSel]),
    ]),
    h("div.field", [h("label", "Data"), data, dataHint]),
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
          form.querySelectorAll(".err").forEach((x) => x.remove());
          if (!name.value.trim()) { name.classList.add("invalid"); return false; }
          if (!data.value.trim()) { data.classList.add("invalid"); return false; }

          const body = {
            name: name.value.trim(),
            type: typeSel.value,
            data: data.value.trim(),
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
            if (err.status === 422 && applyFieldErrors(form, err)) return false;
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
