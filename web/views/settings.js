// Resolver settings: forwarders, forwarding toggle, cache, DNSSEC.

import { api } from "../api.js";
import {
  h, clear, icon, loadingBlock, applyFieldErrors, toast, toastError,
} from "../ui.js";

const PROTOCOLS = ["udp", "tcp", "tls", "https"];
const DEFAULT_PORTS = { udp: 53, tcp: 53, tls: 853, https: 443 };

export async function renderSettings(root) {
  root.appendChild(loadingBlock());
  const { settings } = await api.getSettings();

  const forwardersHost = h("div");
  function addForwarder(f = { addr: "", protocol: "udp", port: 53, tls_name: null }) {
    forwardersHost.appendChild(forwarderRow(f));
  }
  (settings.forwarders && settings.forwarders.length ? settings.forwarders : [])
    .forEach((f) => addForwarder(f));

  const addBtn = h("button.btn.btn-sm", { type: "button" }, [icon("plus", 16), "Add forwarder"]);
  addBtn.addEventListener("click", () => addForwarder());

  const forwardEnabled = h("input", { type: "checkbox", name: "forward_enabled", checked: !!settings.forward_enabled });
  const dnssec = h("input", { type: "checkbox", name: "dnssec_validate_upstream", checked: !!settings.dnssec_validate_upstream });

  const cacheSize = h("input", { type: "number", name: "cache_size", value: settings.cache_size ?? 1024, min: 0 });
  const cacheMin = h("input", { type: "number", name: "cache_min_ttl", value: settings.cache_min_ttl ?? 0, min: 0 });
  const cacheMax = h("input", { type: "number", name: "cache_max_ttl", value: settings.cache_max_ttl ?? 86400, min: 0 });

  const save = h("button.btn.btn-primary", "Save settings");

  const form = h("form", [
    // Forwarding
    h("div.card.section", [
      h("div.card-head", [h("h2", "Forwarding")]),
      h("div.card-pad", [
        h("div.field", [
          h("label.switch", [forwardEnabled, h("span.track"), h("span", "Forward unresolved queries upstream")]),
        ]),
        h("div.field", [
          h("label", "Upstream forwarders"),
          h("div.inline-note", { style: "margin-bottom:8px" },
            "tls and https protocols require a TLS server name."),
          forwardersHost,
          addBtn,
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

    h("div", { style: "display:flex;justify-content:flex-end" }, save),
  ]);

  save.addEventListener("click", async (e) => {
    e.preventDefault();
    form.querySelectorAll(".invalid").forEach((x) => x.classList.remove("invalid"));
    form.querySelectorAll(".err").forEach((x) => x.remove());

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

    if (badRow) {
      toast("tls/https forwarders require a TLS server name.", "error");
      return;
    }

    const body = {
      forwarders,
      forward_enabled: forwardEnabled.checked,
      cache_size: Number(cacheSize.value),
      cache_min_ttl: Number(cacheMin.value),
      cache_max_ttl: Number(cacheMax.value),
      dnssec_validate_upstream: dnssec.checked,
    };

    save.disabled = true;
    try {
      await api.updateSettings(body);
      toast("Settings saved. Resolver updated live.", "success");
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
    // Suggest the conventional port when switching protocol and port is default/empty.
    syncTls();
  });
  syncTls();

  remove.addEventListener("click", () => row.remove());
  return row;
}
