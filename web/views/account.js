// Account: change password and logout.

import { api, ApiError } from "../api.js";
import { h, clear, icon, fmtTime, toast, toastError } from "../ui.js";

export async function renderAccount(root, { ctx }) {
  const user = ctx.user || {};

  // ---- change password form ----
  const current = h("input", { type: "password", name: "current_password", autocomplete: "current-password", required: true });
  const next = h("input", { type: "password", name: "new_password", autocomplete: "new-password", required: true });
  const confirm = h("input", { type: "password", name: "confirm", autocomplete: "new-password", required: true });
  const save = h("button.btn.btn-primary", "Change password");

  function clearErrs() {
    pwForm.querySelectorAll(".invalid").forEach((x) => x.classList.remove("invalid"));
    pwForm.querySelectorAll(".err").forEach((x) => x.remove());
  }
  function fieldErr(input, msg) {
    input.classList.add("invalid");
    const f = input.closest(".field");
    if (f) f.appendChild(h("div.err", msg));
  }

  const pwForm = h("form", [
    h("div.field", [h("label", "Current password"), current]),
    h("div.field", [h("label", "New password"), next, h("div.hint", "At least 12 characters.")]),
    h("div.field", [h("label", "Confirm new password"), confirm]),
    h("div", { style: "display:flex;justify-content:flex-end" }, save),
  ]);

  pwForm.addEventListener("submit", (e) => e.preventDefault());
  save.addEventListener("click", async (e) => {
    e.preventDefault();
    clearErrs();
    if (!current.value) { fieldErr(current, "Required."); return; }
    if (next.value.length < 12) { fieldErr(next, "Must be at least 12 characters."); return; }
    if (next.value !== confirm.value) { fieldErr(confirm, "Passwords do not match."); return; }

    save.disabled = true;
    try {
      await api.changePassword(current.value, next.value);
      toast("Password changed.", "success");
      current.value = next.value = confirm.value = "";
      if (ctx.user) ctx.user.must_change_password = false;
    } catch (err) {
      if (err instanceof ApiError && err.status === 403) {
        fieldErr(current, "Current password is incorrect.");
      } else if (err instanceof ApiError && err.status === 422) {
        fieldErr(next, err.message || "Password does not meet requirements.");
      } else {
        toastError(err);
      }
    } finally {
      save.disabled = false;
    }
  });

  // ---- logout ----
  const logoutBtn = h("button.btn.btn-danger", [icon("logout", 16), "Sign out"]);
  logoutBtn.addEventListener("click", async () => {
    logoutBtn.disabled = true;
    try {
      await api.logout();
    } catch (_) {
      // even if it fails, drop the local session view
    }
    location.hash = "#/login";
    location.reload();
  });

  clear(root).appendChild(h("div", [
    h("div.page-head", [h("div", [h("h1", "Account")])]),

    user.must_change_password
      ? h("div.card.section", { style: "border-color:var(--warning)" },
          h("div.card-pad", h("div.inline-note", { style: "color:var(--warning)" },
            "You are required to change your password.")))
      : null,

    h("div.card.section", { style: "max-width:560px" }, [
      h("div.card-head", [h("h2", "Profile")]),
      h("div.card-pad",
        h("dl.kv", [
          h("dt", "Username"), h("dd.mono", user.username || "-"),
          h("dt", "User ID"), h("dd.mono", user.id != null ? String(user.id) : "-"),
          h("dt", "Created"), h("dd", fmtTime(user.created_at)),
        ])
      ),
    ]),

    h("div.card.section", { style: "max-width:560px" }, [
      h("div.card-head", [h("h2", "Change password")]),
      h("div.card-pad", pwForm),
    ]),

    h("div.card.section", { style: "max-width:560px" }, [
      h("div.card-head", [h("h2", "Session")]),
      h("div.card-pad", [
        h("p.inline-note", { style: "margin-top:0" }, "End this session on this device."),
        logoutBtn,
      ]),
    ]),
  ]));
}
