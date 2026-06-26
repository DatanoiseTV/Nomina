// DNS rewrites: answer a fixed IP or hostname for a domain (and its subdomains).

import { api } from "../api.js";
import {
  h, clear, icon,
  loadingBlock, emptyState, openDialog, confirmDialog,
  applyFieldErrors, toast, toastError,
} from "../ui.js";

export async function renderRewrites(root, { navigate }) {
  root.appendChild(loadingBlock());
  const { rewrites } = await api.listRewrites();
  const reload = () => renderRewrites(root, { navigate });

  const add = h("button.btn.btn-primary", [icon("plus", 16), "New rewrite"]);
  add.addEventListener("click", () => openRewriteDialog({ onSaved: reload }));

  const head = h("div.page-head", [
    h("div", [h("h1", "Rewrites"),
      h("div.subtitle", "Answer a fixed IP or hostname for a domain and its subdomains.")]),
    h("div.spacer"),
    add,
  ]);

  const notice = h("div.notice", [
    icon("shuffle", 18),
    h("div", "A rewrite covers the domain and all of its subdomains, and applies even in authoritative-only (Off) resolution mode. An IP target yields an A/AAAA answer; a hostname yields a CNAME."),
  ]);

  if (!rewrites.length) {
    const b = h("button.btn.btn-primary", [icon("plus", 16), "Add a rewrite"]);
    b.addEventListener("click", () => openRewriteDialog({ onSaved: reload }));
    clear(root).appendChild(h("div", [head, notice,
      h("div.card", emptyState("shuffle", "No rewrites",
        "Redirect a domain to an IP or hostname of your choice.", b))]));
    return;
  }

  const rows = rewrites.map((rw) => row(rw, reload));

  clear(root).appendChild(h("div", [
    head,
    notice,
    h("div.table-wrap",
      h("table.tbl", [
        h("thead", h("tr", [
          h("th", "Domain"), h("th", "Target"), h("th", "Status"),
          h("th", "Comment"), h("th", ""),
        ])),
        h("tbody", rows),
      ])
    ),
  ]));
}

function row(rw, reload) {
  const toggle = h("input", { type: "checkbox", checked: !!rw.enabled, "aria-label": `Enable rewrite for ${rw.domain}` });
  toggle.addEventListener("change", async () => {
    toggle.disabled = true;
    try {
      await api.updateRewrite(rw.id, { enabled: toggle.checked });
      toast(`Rewrite for ${rw.domain} ${toggle.checked ? "enabled" : "disabled"}.`, "success");
      rw.enabled = toggle.checked;
    } catch (err) {
      toggle.checked = !toggle.checked;
      toastError(err);
    } finally {
      toggle.disabled = false;
    }
  });

  const edit = h("button.btn-icon", { title: "Edit rewrite", "aria-label": `Edit rewrite for ${rw.domain}` }, icon("edit", 16));
  edit.addEventListener("click", () => openRewriteDialog({ rewrite: rw, onSaved: reload }));

  const del = h("button.btn-icon", { title: "Delete rewrite", "aria-label": `Delete rewrite for ${rw.domain}` }, icon("trash", 16));
  del.addEventListener("click", () => {
    confirmDialog({
      title: `Delete rewrite for ${rw.domain}?`,
      message: "Queries for this domain will resolve normally again.",
      confirmLabel: "Delete rewrite",
      danger: true,
      onConfirm: async () => {
        try {
          await api.deleteRewrite(rw.id);
          toast(`Rewrite for ${rw.domain} deleted.`, "success");
          reload();
        } catch (err) { toastError(err); throw err; }
      },
    });
  });

  return h("tr", [
    h("td.mono", h("strong", rw.domain)),
    h("td.mono", rw.target),
    h("td", h("label.switch", [toggle, h("span.track")])),
    h("td.wrap", rw.comment ? rw.comment : h("span.inline-note", "-")),
    h("td.actions", h("div", { style: "display:flex;gap:2px;justify-content:flex-end" }, [edit, del])),
  ]);
}

export function openRewriteDialog({ rewrite, prefillDomain, onSaved }) {
  const isEdit = !!rewrite;
  const initialDomain = rewrite ? rewrite.domain : (prefillDomain || "");
  const domain = h("input", { type: "text", name: "domain", value: initialDomain, placeholder: "ads.example.com", required: true });
  const target = h("input", { type: "text", name: "target", value: rewrite ? rewrite.target : "", placeholder: "1.2.3.4 or host.example.com", required: true });
  const comment = h("input", { type: "text", name: "comment", value: rewrite && rewrite.comment ? rewrite.comment : "", placeholder: "optional note" });

  const form = h("form", [
    h("div.field", [h("label", "Domain"), domain,
      h("div.hint", "Matches this domain and every subdomain of it.")]),
    h("div.field", [h("label", "Target"), target,
      h("div.hint", "An IPv4/IPv6 address (A/AAAA) or a hostname (CNAME).")]),
    isEdit ? null : h("div.field", [h("label", "Comment"), comment]),
  ]);

  openDialog({
    title: isEdit ? "Edit rewrite" : "New rewrite",
    body: form,
    actions: [
      { label: "Cancel" },
      {
        label: isEdit ? "Save changes" : "Create rewrite", kind: "primary",
        onClick: async () => {
          form.querySelectorAll(".invalid").forEach((x) => x.classList.remove("invalid"));
          form.querySelectorAll(".err").forEach((x) => x.remove());
          let bad = false;
          if (!domain.value.trim()) { domain.classList.add("invalid"); bad = true; }
          if (!target.value.trim()) { target.classList.add("invalid"); bad = true; }
          if (bad) return false;
          const dom = domain.value.trim();
          const tgt = target.value.trim();
          try {
            if (isEdit) {
              // PUT contract accepts only domain/target/enabled (no comment).
              await api.updateRewrite(rewrite.id, { domain: dom, target: tgt });
              toast(`Rewrite for ${dom} updated.`, "success");
            } else {
              await api.createRewrite({ domain: dom, target: tgt, comment: comment.value.trim() || null });
              toast(`Rewrite for ${dom} created.`, "success");
            }
            onSaved();
          } catch (err) {
            if (err.status === 422 && applyFieldErrors(form, err)) return false;
            if (err.status === 409) { domain.classList.add("invalid"); toast(err.message || "A rewrite for that domain already exists.", "error"); return false; }
            toastError(err);
            return false;
          }
        },
      },
    ],
  });
}
