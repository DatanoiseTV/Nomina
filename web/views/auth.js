// Login and first-run setup screens.

import { api, ApiError } from "../api.js";
import { h, icon, applyFieldErrors } from "../ui.js";

function authShell(subtitle, formNode) {
  return h("div.auth-wrap",
    h("div.auth-card", [
      h("div.auth-brand", [icon("logo", 28), h("span", "PicoNS")]),
      h("p.auth-sub", subtitle),
      formNode,
    ])
  );
}

export function renderLogin(root, { onLoggedIn }) {
  const errorBox = h("div.auth-error", { style: "display:none" });
  const username = h("input", { type: "text", name: "username", autocomplete: "username", required: true, autofocus: true });
  const password = h("input", { type: "password", name: "password", autocomplete: "current-password", required: true });
  const submit = h("button.btn.btn-primary", { type: "submit" }, "Sign in");

  function showError(msg) {
    errorBox.textContent = msg;
    errorBox.style.display = "block";
  }

  const form = h("form", [
    errorBox,
    h("div.field", [h("label", "Username"), username]),
    h("div.field", [h("label", "Password"), password]),
    submit,
  ]);

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    errorBox.style.display = "none";
    [username, password].forEach((i) => i.classList.remove("invalid"));
    if (!username.value || !password.value) {
      showError("Enter your username and password.");
      return;
    }
    submit.disabled = true;
    submit.textContent = "Signing in…";
    try {
      const res = await api.login(username.value, password.value);
      onLoggedIn(res.user);
    } catch (err) {
      if (err instanceof ApiError && err.status === 429) {
        showError("Too many attempts. Please wait a moment and try again.");
      } else if (err instanceof ApiError && err.status === 401) {
        showError("Invalid username or password.");
        password.value = "";
        password.focus();
      } else {
        showError(err.message || "Sign-in failed.");
      }
    } finally {
      submit.disabled = false;
      submit.textContent = "Sign in";
    }
  });

  root.appendChild(authShell("Sign in to manage your DNS server.", form));
  username.focus();
}

export function renderSetup(root, { onDone }) {
  const errorBox = h("div.auth-error", { style: "display:none" });
  const username = h("input", { type: "text", name: "username", autocomplete: "username", required: true });
  const password = h("input", { type: "password", name: "password", autocomplete: "new-password", required: true });
  const confirm = h("input", { type: "password", name: "confirm", autocomplete: "new-password", required: true });
  const submit = h("button.btn.btn-primary", { type: "submit" }, "Create admin account");

  function showError(msg) {
    errorBox.textContent = msg;
    errorBox.style.display = "block";
  }

  const form = h("form", [
    errorBox,
    h("div.field", [h("label", "Admin username"), username,
      h("div.hint", "Letters, numbers, dash and underscore.")]),
    h("div.field", [h("label", "Password"), password,
      h("div.hint", "At least 12 characters.")]),
    h("div.field", [h("label", "Confirm password"), confirm]),
    submit,
  ]);

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    errorBox.style.display = "none";
    [username, password, confirm].forEach((i) => i.classList.remove("invalid"));

    if (password.value.length < 12) {
      password.classList.add("invalid");
      showError("Password must be at least 12 characters.");
      return;
    }
    if (password.value !== confirm.value) {
      confirm.classList.add("invalid");
      showError("Passwords do not match.");
      return;
    }

    submit.disabled = true;
    submit.textContent = "Creating…";
    try {
      // POST /api/setup creates the first admin and (per contract) logs in.
      const res = await api.setup(username.value, password.value);
      const user = res && res.user ? res.user : { id: 0, username: username.value, must_change_password: false };
      onDone(user);
    } catch (err) {
      if (err instanceof ApiError && err.status === 409) {
        showError("Setup has already been completed. Reload to sign in.");
      } else if (err instanceof ApiError && err.status === 422) {
        applyFieldErrors(form, err);
        showError(err.message || "Please check the highlighted fields.");
      } else {
        showError(err.message || "Setup failed.");
      }
    } finally {
      submit.disabled = false;
      submit.textContent = "Create admin account";
    }
  });

  root.appendChild(authShell("Welcome. Create the first administrator account.", form));
  username.focus();
}
