// Resolver settings: resolution mode, forwarders, cache, DNSSEC, blocking.

import { api } from "../api.js";
import {
  h, clear, icon, loadingBlock, applyFieldErrors, toast, toastError,
} from "../ui.js";

const PROTOCOLS = ["udp", "tcp", "tls", "https"];
const DEFAULT_PORTS = { udp: 53, tcp: 53, tls: 853, https: 443 };

const RESOLUTION_MODES = [
  { id: "forward", label: "Forward", desc: "Send unresolved queries to the upstream forwarders below." },
  { id: "recursive", label: "Recursive", desc: "Resolve from the root servers directly; no upstream needed." },
  { id: "off", label: "Off", desc: "Authoritative-only: REFUSE any name outside the local zones." },
];

const BLOCK_MODES = [
  { id: "nxdomain", label: "NXDOMAIN (name does not exist)" },
  { id: "zero_ip", label: "Zero IP (0.0.0.0 / ::)" },
  { id: "refused", label: "REFUSED" },
];

const QUERY_LOG_MODES = [
  { id: "off", label: "Off", desc: "Aggregate stats only — no client IPs or query names retained. Default, privacy-friendly." },
  { id: "anonymized", label: "Anonymized", desc: "Record recent queries and top domains, but mask client IPs to /24 (IPv4) or /48 (IPv6)." },
  { id: "full", label: "Full", desc: "Retain full client IPs and names." },
];

export async function renderSettings(root) {
  root.appendChild(loadingBlock());
  const { settings } = await api.getSettings();
  const original = settings;

  // ---- Resolution mode (segmented control) ----
  let mode = RESOLUTION_MODES.some((m) => m.id === settings.resolution_mode)
    ? settings.resolution_mode : "forward";
  const modeDesc = h("div.inline-note", { style: "margin-top:10px" });
  const forwardingCard = h("div.card.section");

  const segBtns = RESOLUTION_MODES.map((m) =>
    h("button", { type: "button", "aria-pressed": String(m.id === mode), dataset: { mode: m.id } }, m.label)
  );
  const segmented = h("div.segmented", { role: "group", "aria-label": "Resolution mode" }, segBtns);

  function syncMode() {
    segBtns.forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.mode === mode)));
    const def = RESOLUTION_MODES.find((m) => m.id === mode);
    clear(modeDesc).appendChild(document.createTextNode(def ? def.desc : ""));
    // Forwarders only matter in forward mode: grey out + disable inputs (still editable after switching back).
    const fwActive = mode === "forward";
    forwardingCard.classList.toggle("section-disabled", !fwActive);
    forwardingCard.querySelectorAll("input, select, button").forEach((el) => { el.disabled = !fwActive; });
    // Re-apply per-row tls enable/disable (which depends on the protocol) after a blanket enable.
    if (fwActive) {
      forwardersHost.querySelectorAll('[data-k="protocol"]').forEach((p) => p.dispatchEvent(new Event("change")));
    }
  }
  segBtns.forEach((b) => b.addEventListener("click", () => { mode = b.dataset.mode; syncMode(); }));

  // ---- Forwarders ----
  const forwardersHost = h("div");
  function addForwarder(f = { addr: "", protocol: "udp", port: 53, tls_name: null }) {
    forwardersHost.appendChild(forwarderRow(f));
  }
  (settings.forwarders && settings.forwarders.length ? settings.forwarders : [])
    .forEach((f) => addForwarder(f));

  const addBtn = h("button.btn.btn-sm", { type: "button" }, [icon("plus", 16), "Add forwarder"]);
  addBtn.addEventListener("click", () => addForwarder());

  clear(forwardingCard).appendChild(h("div", [
    h("div.card-head", [h("h2", "Forwarders")]),
    h("div.card-pad", [
      h("div.inline-note", { style: "margin-bottom:8px" },
        "Used only when resolution mode is Forward. tls and https protocols require a TLS server name."),
      forwardersHost,
      addBtn,
    ]),
  ]));

  // ---- Blocking ----
  const blockingEnabled = h("input", { type: "checkbox", name: "blocking_enabled", checked: !!settings.blocking_enabled });
  const blockMode = h("select", { name: "block_mode" },
    BLOCK_MODES.map((m) => h("option", { value: m.id, selected: settings.block_mode === m.id }, m.label)));

  // ---- DNSSEC ----
  const dnssec = h("input", { type: "checkbox", name: "dnssec_validate_upstream", checked: !!settings.dnssec_validate_upstream });

  // ---- Privacy / query logging (segmented control) ----
  let queryLog = QUERY_LOG_MODES.some((m) => m.id === settings.query_log) ? settings.query_log : "off";
  const qlDesc = h("div.inline-note", { style: "margin-top:10px" });
  const qlBtns = QUERY_LOG_MODES.map((m) =>
    h("button", { type: "button", "aria-pressed": String(m.id === queryLog), dataset: { ql: m.id } }, m.label)
  );
  const qlSegmented = h("div.segmented", { role: "group", "aria-label": "Query logging mode" }, qlBtns);
  function syncQueryLog() {
    qlBtns.forEach((b) => b.setAttribute("aria-pressed", String(b.dataset.ql === queryLog)));
    const def = QUERY_LOG_MODES.find((m) => m.id === queryLog);
    clear(qlDesc).appendChild(document.createTextNode(def ? def.desc : ""));
  }
  qlBtns.forEach((b) => b.addEventListener("click", () => { queryLog = b.dataset.ql; syncQueryLog(); }));

  // ---- AXFR allow-list (CIDR editor) ----
  const axfrHost = h("div");
  const seedAxfr = settings.allow_axfr_from && settings.allow_axfr_from.length ? settings.allow_axfr_from : [];
  seedAxfr.forEach((c) => axfrHost.appendChild(cidrRow(c)));
  const addAxfr = h("button.btn.btn-sm", { type: "button" }, [icon("plus", 16), "Add network"]);
  addAxfr.addEventListener("click", () => axfrHost.appendChild(cidrRow()));

  // ---- Cache ----
  const cacheSize = h("input", { type: "number", name: "cache_size", value: settings.cache_size ?? 1024, min: 0 });
  const cacheMin = h("input", { type: "number", name: "cache_min_ttl", value: settings.cache_min_ttl ?? 0, min: 0 });
  const cacheMax = h("input", { type: "number", name: "cache_max_ttl", value: settings.cache_max_ttl ?? 86400, min: 0 });

  const save = h("button.btn.btn-primary", "Save settings");

  const form = h("form", [
    // Resolution mode
    h("div.card.section", [
      h("div.card-head", [h("h2", "Resolution mode")]),
      h("div.card-pad", [segmented, modeDesc]),
    ]),

    forwardingCard,

    // Blocking
    h("div.card.section", [
      h("div.card-head", [h("h2", "Blocking")]),
      h("div.card-pad", [
        h("div.field", [
          h("label.switch", [blockingEnabled, h("span.track"), h("span", "Enable blocklist filtering")]),
          h("div.hint", "Manual allow/deny rules and rewrites still apply when this is off."),
        ]),
        h("div.field", { style: "max-width:320px" }, [
          h("label", "Block mode"), blockMode,
          h("div.hint", "How blocked names are answered."),
        ]),
      ]),
    ]),

    // Cache
    h("div.card.section", [
      h("div.card-head", [h("h2", "Cache")]),
      h("div.card-pad", h("div.form-row", [
        h("div.field", [h("label", "Cache size (entries)"), cacheSize]),
        h("div.field", [h("label", "Min TTL (seconds)"), cacheMin]),
        h("div.field", [h("label", "Max TTL (seconds)"), cacheMax]),
      ])),
    ]),

    // DNSSEC
    h("div.card.section", [
      h("div.card-head", [h("h2", "DNSSEC")]),
      h("div.card-pad", h("div.field", [
        h("label.switch", [dnssec, h("span.track"), h("span", "Validate upstream responses (DNSSEC)")]),
      ])),
    ]),

    // Privacy / query logging
    h("div.card.section", [
      h("div.card-head", [h("h2", "Privacy / Query logging")]),
      h("div.card-pad", [
        h("div.inline-note", { style: "margin-bottom:10px" },
          "Controls per-query retention shown on the dashboard (recent queries, top domains)."),
        qlSegmented,
        qlDesc,
      ]),
    ]),

    // AXFR allow-list
    h("div.card.section", [
      h("div.card-head", [h("h2", "Zone transfer (AXFR)")]),
      h("div.card-pad", [
        h("div.inline-note", { style: "margin-bottom:8px" },
          "Allow secondaries from these networks (empty = disabled)."),
        axfrHost,
        addAxfr,
      ]),
    ]),

    h("div", { style: "display:flex;justify-content:flex-end" }, save),
  ]);

  syncMode();
  syncQueryLog();

  save.addEventListener("click", async (e) => {
    e.preventDefault();
    form.querySelectorAll(".invalid").forEach((x) => x.classList.remove("invalid"));
    form.querySelectorAll(".err").forEach((x) => x.remove());

    // Collect forwarders (read regardless of disabled state so the list is preserved).
    const forwarders = [];
    let badRow = false;
    forwardersHost.querySelectorAll("[data-forwarder]").forEach((row) => {
      const addr = row.querySelector('[data-k="addr"]');
      const proto = row.querySelector('[data-k="protocol"]');
      const port = row.querySelector('[data-k="port"]');
      const tls = row.querySelector('[data-k="tls_name"]');
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

    if (mode === "forward" && badRow) {
      toast("tls/https forwarders require a TLS server name.", "error");
      return;
    }

    // Collect AXFR allow-list CIDRs (skip empties).
    const allowAxfr = [...axfrHost.querySelectorAll("input")]
      .map((i) => i.value.trim())
      .filter(Boolean);

    // Build a partial body: only fields that changed from the loaded settings.
    const next = {
      forwarders,
      resolution_mode: mode,
      block_mode: blockMode.value,
      blocking_enabled: blockingEnabled.checked,
      query_log: queryLog,
      allow_axfr_from: allowAxfr,
      cache_size: Number(cacheSize.value),
      cache_min_ttl: Number(cacheMin.value),
      cache_max_ttl: Number(cacheMax.value),
      dnssec_validate_upstream: dnssec.checked,
    };

    const ARRAY_FIELDS = new Set(["forwarders", "allow_axfr_from"]);
    const body = {};
    for (const [k, v] of Object.entries(next)) {
      const changed = ARRAY_FIELDS.has(k)
        ? JSON.stringify(v) !== JSON.stringify(original[k] || [])
        : v !== original[k];
      if (changed) body[k] = v;
    }

    if (Object.keys(body).length === 0) {
      toast("No changes to save.", "info");
      return;
    }

    save.disabled = true;
    try {
      await api.updateSettings(body);
      toast("Settings saved. Resolver updated live.", "success");
      renderSettings(root);
    } catch (err) {
      if (!(err.status === 422 && applyFieldErrors(form, err))) toastError(err);
    } finally {
      save.disabled = false;
    }
  });

  clear(root).appendChild(h("div", [
    h("div.page-head", [
      h("div", [h("h1", "Settings"),
        h("div.subtitle", "Listen addresses and TLS certificates are startup config and not editable here.")]),
    ]),
    form,
  ]));
}

function cidrRow(value = "") {
  const input = h("input", { type: "text", value, placeholder: "192.168.0.0/24" });
  const remove = h("button.btn-icon", { type: "button", title: "Remove", "aria-label": "Remove network" }, icon("close", 16));
  const row = h("div.repeat-row", [input, remove]);
  remove.addEventListener("click", () => row.remove());
  return row;
}

function forwarderRow(f) {
  const addr = h("input", { type: "text", value: f.addr || "", placeholder: "1.1.1.1", dataset: { k: "addr" } });
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
  proto.addEventListener("change", () => {
    syncTls();
  });
  syncTls();

  remove.addEventListener("click", () => row.remove());
  return row;
}
