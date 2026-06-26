// PicoNS SPA bootstrap, hash router, and app shell.

import { api, ApiError } from "./api.js";
import { h, clear, icon, initials, toast, toastError } from "./ui.js";

import { renderLogin, renderSetup } from "./views/auth.js";
import { renderDashboard } from "./views/dashboard.js";
import { renderZones } from "./views/zones.js";
import { renderZoneDetail } from "./views/zone-detail.js";
import { renderViews } from "./views/views.js";
import { renderSettings } from "./views/settings.js";
import { renderAccount } from "./views/account.js";
import { renderBlocklists } from "./views/blocklists.js";
import { renderRules } from "./views/rules.js";
import { renderRewrites } from "./views/rewrites.js";

// ---- Theme -----------------------------------------------------------------
const THEME_KEY = "picons-theme";

export function getTheme() {
  return localStorage.getItem(THEME_KEY) || "system";
}
export function setTheme(theme) {
  localStorage.setItem(THEME_KEY, theme);
  document.documentElement.setAttribute("data-theme", theme);
  updateThemeButton();
}
function effectiveDark() {
  const t = getTheme();
  if (t === "dark") return true;
  if (t === "light") return false;
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}
function cycleTheme() {
  setTheme(effectiveDark() ? "light" : "dark");
}
function updateThemeButton() {
  const btn = document.getElementById("theme-toggle");
  if (!btn) return;
  clear(btn);
  btn.appendChild(icon(effectiveDark() ? "sun" : "moon", 18));
  btn.title = effectiveDark() ? "Switch to light mode" : "Switch to dark mode";
}
document.documentElement.setAttribute("data-theme", getTheme());

// ---- App state -------------------------------------------------------------
const state = {
  user: null,
  appEl: null,
  contentEl: null,
};

// ---- Routes ----------------------------------------------------------------
const routes = [
  { re: /^\/?$/, view: renderDashboard, nav: "dashboard", title: "Dashboard" },
  { re: /^\/dashboard$/, view: renderDashboard, nav: "dashboard", title: "Dashboard" },
  { re: /^\/zones$/, view: renderZones, nav: "zones", title: "Zones" },
  { re: /^\/zones\/(\d+)$/, view: renderZoneDetail, nav: "zones", title: "Zone" },
  { re: /^\/views$/, view: renderViews, nav: "views", title: "Views" },
  { re: /^\/blocklists$/, view: renderBlocklists, nav: "blocklists", title: "Blocklists" },
  { re: /^\/rules$/, view: renderRules, nav: "rules", title: "Rules" },
  { re: /^\/rewrites$/, view: renderRewrites, nav: "rewrites", title: "Rewrites" },
  { re: /^\/settings$/, view: renderSettings, nav: "settings", title: "Settings" },
  { re: /^\/account$/, view: renderAccount, nav: "account", title: "Account" },
];

const NAV_ITEMS = [
  { id: "dashboard", label: "Dashboard", href: "#/dashboard", icon: "dashboard" },
  { id: "zones", label: "Zones", href: "#/zones", icon: "zones" },
  { id: "views", label: "Views", href: "#/views", icon: "views" },
  { section: "Filtering" },
  { id: "blocklists", label: "Blocklists", href: "#/blocklists", icon: "shield" },
  { id: "rules", label: "Rules", href: "#/rules", icon: "filter" },
  { id: "rewrites", label: "Rewrites", href: "#/rewrites", icon: "shuffle" },
  { section: "System" },
  { id: "settings", label: "Settings", href: "#/settings", icon: "settings" },
  { id: "account", label: "Account", href: "#/account", icon: "account" },
];

function currentPath() {
  const hash = location.hash || "#/";
  return hash.replace(/^#/, "") || "/";
}

// ---- Shell -----------------------------------------------------------------
function buildShell() {
  const nav = h("nav.nav", { "aria-label": "Primary" },
    NAV_ITEMS.map((item) =>
      item.section
        ? h("div.nav-section", item.section)
        : h("a", { href: item.href, dataset: { nav: item.id } }, [
            icon(item.icon, 18),
            h("span", item.label),
          ])
    )
  );

  const themeBtn = h("button.btn-icon#theme-toggle", { type: "button", "aria-label": "Toggle theme" });
  themeBtn.addEventListener("click", cycleTheme);

  const sidebar = h("aside.sidebar", [
    h("div.brand", [icon("logo", 26), h("span", "PicoNS")]),
    nav,
    h("div.sidebar-footer",
      h("a", { href: "#/account", dataset: { nav: "account" }, class: "user-chip" }, [
        h("span.avatar", initials(state.user.username)),
        h("span", state.user.username),
      ])
    ),
  ]);

  const hamburger = h("button.btn-icon.hamburger", { type: "button", "aria-label": "Open menu" }, icon("menu", 20));
  hamburger.addEventListener("click", () => shell.classList.add("nav-open"));

  const topbar = h("header.topbar", [
    hamburger,
    h("div.page-title#page-title", "Dashboard"),
    h("div.spacer"),
    themeBtn,
  ]);

  const content = h("main.content", h("div.content-inner#content-inner"));
  state.contentEl = content.querySelector("#content-inner");

  const scrim = h("div.scrim");
  scrim.addEventListener("click", () => shell.classList.remove("nav-open"));

  const shell = h("div.shell", [sidebar, h("div.main", [topbar, content]), scrim]);

  // Close mobile nav on navigation
  nav.addEventListener("click", () => shell.classList.remove("nav-open"));

  clear(state.appEl).appendChild(shell);
  state.appEl.removeAttribute("aria-busy");
  updateThemeButton();
}

function setActiveNav(navId, title) {
  document.querySelectorAll(".nav a[data-nav]").forEach((a) => {
    a.classList.toggle("active", a.dataset.nav === navId);
  });
  const pt = document.getElementById("page-title");
  if (pt) pt.textContent = title;
}

// ---- Router ----------------------------------------------------------------
let routeToken = 0;
let activeCleanup = null;

function runCleanup() {
  if (activeCleanup) {
    try { activeCleanup(); } catch (_) {}
    activeCleanup = null;
  }
}

async function handleRoute() {
  if (!state.user) return;
  if (!document.querySelector(".shell")) buildShell();

  runCleanup();

  const path = currentPath();
  const token = ++routeToken;

  for (const r of routes) {
    const m = path.match(r.re);
    if (m) {
      setActiveNav(r.nav, r.title);
      const params = m.slice(1);
      const root = clear(state.contentEl);
      const registerCleanup = (fn) => { activeCleanup = fn; };
      try {
        await r.view(root, { params, navigate, ctx: state, registerCleanup });
      } catch (e) {
        if (token !== routeToken) return; // superseded
        handleViewError(e, root);
      }
      state.contentEl.parentElement.scrollTop = 0;
      return;
    }
  }
  // Unknown route -> dashboard
  navigate("#/dashboard");
}

function handleViewError(e, root) {
  if (e instanceof ApiError && e.status === 401) {
    onUnauthorized();
    return;
  }
  toastError(e, "Failed to load this view.");
  clear(root).appendChild(
    h("div.empty", [
      h("h3", "Could not load"),
      h("p", e && e.message ? e.message : "Unexpected error."),
      (() => {
        const b = h("button.btn", "Retry");
        b.addEventListener("click", () => handleRoute());
        return b;
      })(),
    ])
  );
}

export function navigate(hash) {
  if (location.hash === hash) handleRoute();
  else location.hash = hash;
}

// ---- Auth lifecycle --------------------------------------------------------
export function onUnauthorized() {
  state.user = null;
  toast("Your session expired. Please sign in again.", "info");
  showAuth("login");
}

export function onLoggedIn(user) {
  state.user = user;
  if (user && user.must_change_password) {
    toast("You must change your password before continuing.", "info", 7000);
  }
  buildShell();
  if (!location.hash || location.hash === "#/login") location.hash = "#/dashboard";
  handleRoute();
}

function showAuth(kind) {
  const root = clear(state.appEl);
  root.removeAttribute("aria-busy");
  if (kind === "setup") renderSetup(root, { onDone: onLoggedIn });
  else renderLogin(root, { onLoggedIn });
}

async function bootstrap() {
  state.appEl = document.getElementById("app");
  try {
    const res = await api.me();
    onLoggedIn(res.user);
  } catch (e) {
    if (e instanceof ApiError) {
      if (e.status === 409 || e.code === "setup_required") {
        showAuth("setup");
        return;
      }
      if (e.status === 401) {
        showAuth("login");
        return;
      }
    }
    // Network or unexpected -> show login with a note
    showAuth("login");
    toastError(e, "Could not reach the server.");
  }
}

window.addEventListener("picons:unauthorized", onUnauthorized);
window.addEventListener("hashchange", handleRoute);
window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", updateThemeButton);

bootstrap();
