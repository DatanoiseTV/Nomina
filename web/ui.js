// Shared UI helpers: DOM builder, inline SVG icons, toasts, dialogs, formatting.

// ---- DOM builder -----------------------------------------------------------
// h("div.card#id", { onclick }, [children]) -> HTMLElement
export function h(tag, attrs, children) {
  let tagName = "div";
  const classes = [];
  let id = null;

  const m = String(tag).match(/^([a-zA-Z0-9]+)?((?:[.#][\w-]+)*)$/);
  if (m) {
    if (m[1]) tagName = m[1];
    const rest = m[2] || "";
    for (const tok of rest.match(/[.#][\w-]+/g) || []) {
      if (tok[0] === ".") classes.push(tok.slice(1));
      else id = tok.slice(1);
    }
  } else {
    tagName = tag;
  }

  const el = document.createElement(tagName);
  if (id) el.id = id;
  if (classes.length) el.className = classes.join(" ");

  // attrs is optional; allow h(tag, children)
  if (attrs && (Array.isArray(attrs) || attrs instanceof Node || typeof attrs === "string")) {
    children = attrs;
    attrs = null;
  }

  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v == null || v === false) continue;
      if (k === "class") el.className = [el.className, v].filter(Boolean).join(" ");
      else if (k === "html") el.innerHTML = v;
      else if (k === "dataset") Object.assign(el.dataset, v);
      else if (k.startsWith("on") && typeof v === "function")
        el.addEventListener(k.slice(2).toLowerCase(), v);
      else if (k === "value") el.value = v;
      else if (k === "checked" || k === "disabled" || k === "selected" || k === "required")
        el[k] = !!v;
      else el.setAttribute(k, v);
    }
  }

  appendChildren(el, children);
  return el;
}

function appendChildren(el, children) {
  if (children == null) return;
  if (Array.isArray(children)) {
    for (const c of children) appendChildren(el, c);
  } else if (children instanceof Node) {
    el.appendChild(children);
  } else {
    el.appendChild(document.createTextNode(String(children)));
  }
}

export function clear(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
  return el;
}

export function svg(pathMarkup, size) {
  const wrap = document.createElement("span");
  wrap.style.display = "inline-flex";
  wrap.innerHTML =
    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" ` +
    `stroke-linecap="round" stroke-linejoin="round"` +
    (size ? ` width="${size}" height="${size}"` : "") +
    `>${pathMarkup}</svg>`;
  return wrap.firstChild;
}

// ---- Icons (feather-style stroke paths) ------------------------------------
export const icons = {
  logo: `<circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="3.5"/>`,
  dashboard: `<rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/>`,
  zones: `<path d="M3 7l9-4 9 4-9 4-9-4z"/><path d="M3 12l9 4 9-4"/><path d="M3 17l9 4 9-4"/>`,
  views: `<circle cx="12" cy="12" r="3"/><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/>`,
  settings: `<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.6 1.6 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.6 1.6 0 0 0-1.8-.3 1.6 1.6 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.6 1.6 0 0 0-1-1.5 1.6 1.6 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.6 1.6 0 0 0 .3-1.8 1.6 1.6 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.6 1.6 0 0 0 1.5-1 1.6 1.6 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.6 1.6 0 0 0 1.8.3H9a1.6 1.6 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.6 1.6 0 0 0 1 1.5 1.6 1.6 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.6 1.6 0 0 0-.3 1.8V9a1.6 1.6 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.6 1.6 0 0 0-1.5 1z"/>`,
  account: `<path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>`,
  plus: `<path d="M12 5v14M5 12h14"/>`,
  trash: `<path d="M3 6h18"/><path d="M8 6V4a1 1 0 0 1 1-1h6a1 1 0 0 1 1 1v2"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/>`,
  edit: `<path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.1 2.1 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>`,
  close: `<path d="M18 6 6 18M6 6l12 12"/>`,
  menu: `<path d="M3 12h18M3 6h18M3 18h18"/>`,
  sun: `<circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/>`,
  moon: `<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/>`,
  download: `<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M7 10l5 5 5-5"/><path d="M12 15V3"/>`,
  upload: `<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M17 8l-5-5-5 5"/><path d="M12 3v12"/>`,
  logout: `<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="M16 17l5-5-5-5"/><path d="M21 12H9"/>`,
  back: `<path d="M19 12H5M12 19l-7-7 7-7"/>`,
  refresh: `<path d="M23 4v6h-6M1 20v-6h6"/><path d="M3.5 9a9 9 0 0 1 14.9-3.4L23 10M1 14l4.6 4.4A9 9 0 0 0 20.5 15"/>`,
  inbox: `<path d="M22 12h-6l-2 3h-4l-2-3H2"/><path d="M5.5 5.6 2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.5-6.4A2 2 0 0 0 16.7 4H7.3a2 2 0 0 0-1.8 1.6z"/>`,
  shield: `<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>`,
  filter: `<path d="M22 3H2l8 9.5V19l4 2v-8.5L22 3z"/>`,
  shuffle: `<path d="M16 3h5v5"/><path d="M4 20 21 3"/><path d="M21 16v5h-5"/><path d="M15 15l6 6"/><path d="M4 4l5 5"/>`,
  block: `<circle cx="12" cy="12" r="9"/><path d="M5.6 5.6l12.8 12.8"/>`,
};

export function icon(name, size) {
  return svg(icons[name] || "", size);
}

// ---- Toasts ----------------------------------------------------------------
export function toast(message, type = "info", timeout = 4500) {
  const root = document.getElementById("toast-root");
  if (!root) return;
  const close = h("button.close", { "aria-label": "Dismiss" }, icon("close", 16));
  const node = h(`div.toast.${type}`, { role: "status" }, [
    h("div.msg", message),
    close,
  ]);
  const dismiss = () => {
    node.style.opacity = "0";
    setTimeout(() => node.remove(), 150);
  };
  close.addEventListener("click", dismiss);
  root.appendChild(node);
  if (timeout) setTimeout(dismiss, timeout);
}

export function toastError(err, fallback = "Something went wrong.") {
  const msg = err && err.message ? err.message : fallback;
  toast(msg, "error", 6000);
}

// ---- Modal dialog ----------------------------------------------------------
// openDialog({ title, body: Node, actions: [{label, kind, onClick, keepOpen}], onClose })
// Returns the <dialog> element. Returning a Promise that rejects from an action
// onClick keeps the dialog open; resolving (or void) closes it unless keepOpen.
export function openDialog({ title, body, actions = [], width, onClose }) {
  const dlg = document.createElement("dialog");
  if (width) dlg.style.width = width;

  const closeBtn = h("button.btn-icon", { type: "button", "aria-label": "Close" }, icon("close", 18));
  const foot = h("div.dialog-foot");
  // Hidden submit button so Enter inside any field submits the form.
  const hiddenSubmit = h("button", { type: "submit", "aria-hidden": "true", tabindex: "-1",
    style: "position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0 0 0 0);border:0" });

  const form = h("form", [
    h("div.dialog-head", [h("h2", title || ""), h("div.spacer"), closeBtn]),
    h("div.dialog-body", [body, hiddenSubmit]),
    foot,
  ]);
  dlg.appendChild(form);

  let primaryBtn = null;
  for (const a of actions) {
    const btn = h(
      `button.btn${a.kind ? ".btn-" + a.kind : ""}`,
      { type: "button" },
      a.label
    );
    btn.addEventListener("click", async () => {
      if (!a.onClick) {
        dlg.close();
        return;
      }
      btn.disabled = true;
      try {
        const r = await a.onClick();
        if (r !== false && !a.keepOpen) dlg.close();
      } catch (e) {
        // action decides messaging; keep open
      } finally {
        btn.disabled = false;
      }
    });
    foot.appendChild(btn);
    if (a.onClick && (!primaryBtn || a.kind === "primary" || a.kind === "danger")) primaryBtn = btn;
  }

  // Enter submits -> trigger the primary action instead of the default dialog close.
  form.addEventListener("submit", (e) => {
    e.preventDefault();
    if (primaryBtn && !primaryBtn.disabled) primaryBtn.click();
  });

  closeBtn.addEventListener("click", () => dlg.close());
  dlg.addEventListener("close", () => {
    if (onClose) onClose();
    dlg.remove();
  });

  document.body.appendChild(dlg);
  dlg.showModal();
  // focus first input for keyboard users
  const firstInput = dlg.querySelector("input, select, textarea, button.btn");
  if (firstInput) firstInput.focus();
  return dlg;
}

export function confirmDialog({ title, message, confirmLabel = "Confirm", danger = false, onConfirm }) {
  return openDialog({
    title: title || "Are you sure?",
    body: h("p", message || ""),
    actions: [
      { label: "Cancel" },
      { label: confirmLabel, kind: danger ? "danger" : "primary", onClick: onConfirm },
    ],
  });
}

// ---- Formatting ------------------------------------------------------------
export function fmtInt(n) {
  if (n == null || isNaN(n)) return "0";
  return Number(n).toLocaleString("en-US");
}

export function fmtUptime(seconds) {
  if (seconds == null) return "-";
  let s = Math.floor(seconds);
  const d = Math.floor(s / 86400); s -= d * 86400;
  const h = Math.floor(s / 3600); s -= h * 3600;
  const m = Math.floor(s / 60); s -= m * 60;
  const parts = [];
  if (d) parts.push(d + "d");
  if (h || d) parts.push(h + "h");
  if (m || h || d) parts.push(m + "m");
  parts.push(s + "s");
  return parts.join(" ");
}

export function fmtTime(iso) {
  if (!iso) return "-";
  const dt = new Date(iso);
  if (isNaN(dt.getTime())) return iso;
  return dt.toLocaleString();
}

export function fmtClock(iso) {
  if (!iso) return "-";
  const dt = new Date(iso);
  if (isNaN(dt.getTime())) return iso;
  return dt.toLocaleTimeString();
}

export function initials(name) {
  if (!name) return "?";
  return name.slice(0, 2).toUpperCase();
}

// ---- Reusable bits ---------------------------------------------------------
export function loadingBlock() {
  return h("div.loading-block", h("div.spinner", { role: "status", "aria-label": "Loading" }));
}

export function emptyState(iconName, title, text, action) {
  return h("div.empty", [
    icon(iconName, 40),
    h("h3", title),
    text ? h("p", text) : null,
    action || null,
  ]);
}

export function badge(text, kind) {
  return h(`span.badge.badge-${kind}`, text);
}

export function onOffBadge(enabled) {
  return enabled
    ? h("span.badge.badge-on", [h("span.dot"), "Enabled"])
    : h("span.badge.badge-off", [h("span.dot"), "Disabled"]);
}

// Apply per-field validation errors from an ApiError onto inputs in a container.
export function applyFieldErrors(container, err) {
  if (!err || !err.fields) return false;
  let applied = false;
  for (const [name, reason] of Object.entries(err.fields)) {
    const input = container.querySelector(`[name="${CSS.escape(name)}"]`);
    if (input) {
      input.classList.add("invalid");
      const f = input.closest(".field");
      if (f) {
        f.querySelectorAll(".err").forEach((e) => e.remove());
        f.appendChild(h("div.err", reason));
      }
      applied = true;
    }
  }
  return applied;
}
