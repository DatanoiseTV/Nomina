// Per-row quick actions for the request log: block / allow a domain or open a
// prefilled rewrite. Shared by the dashboard recent-queries table and the
// full query-log page.

import { api } from "../api.js";
import { h, icon, toast, toastError } from "../ui.js";
import { openRewriteDialog } from "./rewrites.js";

// Strip a trailing dot and lowercase, matching how the API normalizes domains.
function norm(name) {
  return String(name || "").trim().replace(/\.$/, "").toLowerCase();
}

async function addRule(name, action, onChanged) {
  try {
    await api.createRule({ domain: name, action, comment: "added from request log" });
    toast(action === "deny" ? `Blocking ${name}.` : `Allowing ${name}.`, "success");
    if (onChanged) onChanged();
  } catch (err) {
    if (err.status === 409) toast(`A rule for ${name} already exists.`, "info");
    else toastError(err);
  }
}

/// Build the action-button group for a single query row. `onChanged` is called
/// after a rule/rewrite is created so the caller can refresh counters.
export function queryActions(rawName, onChanged) {
  const name = norm(rawName);
  const mk = (iconName, title, handler) => {
    const b = h("button.btn-icon.btn-icon-sm", { type: "button", title, "aria-label": title }, icon(iconName, 15));
    b.addEventListener("click", (e) => {
      e.stopPropagation();
      handler();
    });
    return b;
  };

  // No actionable domain (e.g. empty/root) -> render nothing.
  if (!name) return h("span.inline-note", "-");

  const block = mk("block", `Block ${name}`, () => addRule(name, "deny", onChanged));
  const allow = mk("shield", `Allow ${name}`, () => addRule(name, "allow", onChanged));
  const rewrite = mk("shuffle", `Rewrite ${name}`, () =>
    openRewriteDialog({ prefillDomain: name, onSaved: onChanged || (() => {}) }));

  return h("div", { style: "display:flex;gap:2px;justify-content:flex-end" }, [block, allow, rewrite]);
}
