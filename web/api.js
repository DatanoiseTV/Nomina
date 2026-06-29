// Centralized API client for Nomina.
// Handles cookies, CSRF, error parsing, and typed errors.

export class ApiError extends Error {
  constructor(status, code, message, fields) {
    super(message || code || `HTTP ${status}`);
    this.name = "ApiError";
    this.status = status;
    this.code = code || null;
    this.fields = fields || null;
  }
}

function readCookie(name) {
  const prefix = name + "=";
  for (const part of document.cookie.split(";")) {
    const c = part.trim();
    if (c.startsWith(prefix)) return decodeURIComponent(c.slice(prefix.length));
  }
  return null;
}

const MUTATING = new Set(["POST", "PUT", "PATCH", "DELETE"]);

async function request(method, path, body, opts = {}) {
  const headers = {};
  let payload;

  if (body !== undefined && body !== null) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }

  if (MUTATING.has(method)) {
    const token = readCookie("nomina_csrf");
    if (token) headers["X-CSRF-Token"] = token;
  }

  let res;
  try {
    res = await fetch(path, {
      method,
      headers,
      body: payload,
      credentials: "same-origin",
    });
  } catch (networkErr) {
    throw new ApiError(0, "network_error", "Network error: could not reach the server.");
  }

  if (res.status === 204) return null;

  const ctype = res.headers.get("Content-Type") || "";

  if (opts.raw) {
    if (!res.ok) await throwFromResponse(res, ctype);
    return res.text();
  }

  let data = null;
  if (ctype.includes("application/json")) {
    data = await res.json().catch(() => null);
  } else {
    const text = await res.text().catch(() => "");
    data = text ? { _text: text } : null;
  }

  if (!res.ok) {
    const err = data && data.error ? data.error : {};
    throw new ApiError(res.status, err.code, err.message, err.fields);
  }
  return data;
}

async function throwFromResponse(res, ctype) {
  let err = {};
  if (ctype.includes("application/json")) {
    const data = await res.json().catch(() => null);
    if (data && data.error) err = data.error;
  }
  throw new ApiError(res.status, err.code, err.message, err.fields);
}

export const api = {
  get: (path, opts) => request("GET", path, undefined, opts),
  post: (path, body) => request("POST", path, body ?? {}),
  put: (path, body) => request("PUT", path, body ?? {}),
  patch: (path, body) => request("PATCH", path, body ?? {}),
  del: (path) => request("DELETE", path),

  // ---- Auth ----
  me: () => request("GET", "/api/auth/me"),
  login: (username, password) =>
    request("POST", "/api/auth/login", { username, password }),
  logout: () => request("POST", "/api/auth/logout"),
  setup: (username, password) =>
    request("POST", "/api/setup", { username, password }),
  changePassword: (current_password, new_password) =>
    request("POST", "/api/auth/change-password", { current_password, new_password }),

  // ---- Status / stats ----
  status: () => request("GET", "/api/status"),
  stats: () => request("GET", "/api/stats"),
  mapPoints: () => request("GET", "/api/map"),
  clearStats: () => request("POST", "/api/stats/clear"),

  // ---- Views ----
  listViews: () => request("GET", "/api/views"),
  createView: (body) => request("POST", "/api/views", body),
  updateView: (id, body) => request("PUT", `/api/views/${id}`, body),
  deleteView: (id) => request("DELETE", `/api/views/${id}`),

  // ---- Zones ----
  listZones: () => request("GET", "/api/zones"),
  getZone: (id) => request("GET", `/api/zones/${id}`),
  createZone: (body) => request("POST", "/api/zones", body),
  updateZone: (id, body) => request("PUT", `/api/zones/${id}`, body),
  deleteZone: (id) => request("DELETE", `/api/zones/${id}`),
  exportZoneUrl: (id) => `/api/zones/${id}/export`,
  importZone: (id, zonefile, replace) =>
    request("POST", `/api/zones/${id}/import`, { zonefile, replace: !!replace }),

  // ---- Records ----
  createRecord: (zoneId, body) =>
    request("POST", `/api/zones/${zoneId}/records`, body),
  updateRecord: (id, body) => request("PUT", `/api/records/${id}`, body),
  deleteRecord: (id) => request("DELETE", `/api/records/${id}`),

  // ---- Secondary (slave) zones ----
  // Deletion reuses deleteZone(zone_id); the secondary is the zone.
  listSecondaries: () => request("GET", "/api/secondary-zones"),
  createSecondary: (name, primary) =>
    request("POST", "/api/secondary-zones", { name, primary }),
  refreshSecondary: (id) => request("POST", `/api/secondary-zones/${id}/refresh`, {}),

  // ---- DNSSEC (per-zone online signing) ----
  getDnssec: (id) => request("GET", `/api/zones/${id}/dnssec`),
  enableDnssec: (id) => request("POST", `/api/zones/${id}/dnssec`, {}),
  disableDnssec: (id) => request("DELETE", `/api/zones/${id}/dnssec`),

  // ---- Settings ----
  getSettings: () => request("GET", "/api/settings"),
  updateSettings: (body) => request("PUT", "/api/settings", body),

  // ---- Filtering: blocklists ----
  listBlocklists: () => request("GET", "/api/blocklists"),
  blocklistCatalog: () => request("GET", "/api/blocklists/catalog"),
  createBlocklist: (body) => request("POST", "/api/blocklists", body),
  updateBlocklist: (id, body) => request("PUT", `/api/blocklists/${id}`, body),
  deleteBlocklist: (id) => request("DELETE", `/api/blocklists/${id}`),
  refreshBlocklist: (id) => request("POST", `/api/blocklists/${id}/refresh`, {}),
  refreshAllBlocklists: () => request("POST", "/api/blocklists/refresh_all", {}),

  // ---- Filtering: rules ----
  listRules: () => request("GET", "/api/rules"),
  createRule: (body) => request("POST", "/api/rules", body),
  deleteRule: (id) => request("DELETE", `/api/rules/${id}`),

  // ---- Filtering: rewrites ----
  listRewrites: () => request("GET", "/api/rewrites"),
  createRewrite: (body) => request("POST", "/api/rewrites", body),
  updateRewrite: (id, body) => request("PUT", `/api/rewrites/${id}`, body),
  deleteRewrite: (id) => request("DELETE", `/api/rewrites/${id}`),

  // ---- Conditional forwarding ----
  listConditionalForwards: () => request("GET", "/api/conditional-forwards"),
  createConditionalForward: (body) => request("POST", "/api/conditional-forwards", body),
  updateConditionalForward: (id, body) => request("PUT", `/api/conditional-forwards/${id}`, body),
  deleteConditionalForward: (id) => request("DELETE", `/api/conditional-forwards/${id}`),

  // ---- Query log (persistent, paginated) ----
  queryLog: (params) => {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(params || {})) {
      if (v !== undefined && v !== null && v !== "") qs.set(k, v);
    }
    const s = qs.toString();
    return request("GET", `/api/queries${s ? "?" + s : ""}`);
  },
  clearQueryLog: () => request("DELETE", "/api/queries"),

  // ---- DynDNS tokens ----
  listDyndnsTokens: () => request("GET", "/api/dyndns/tokens"),
  createDyndnsToken: (body) => request("POST", "/api/dyndns/tokens", body),
  deleteDyndnsToken: (id) => request("DELETE", `/api/dyndns/tokens/${id}`),

  // ---- DHCP ----
  listDhcpScopes: () => request("GET", "/api/dhcp/scopes"),
  getDhcpScope: (id) => request("GET", `/api/dhcp/scopes/${id}`),
  createDhcpScope: (body) => request("POST", "/api/dhcp/scopes", body),
  updateDhcpScope: (id, body) => request("PUT", `/api/dhcp/scopes/${id}`, body),
  deleteDhcpScope: (id) => request("DELETE", `/api/dhcp/scopes/${id}`),
  createDhcpReservation: (scopeId, body) => request("POST", `/api/dhcp/scopes/${scopeId}/reservations`, body),
  updateDhcpReservation: (id, body) => request("PUT", `/api/dhcp/reservations/${id}`, body),
  deleteDhcpReservation: (id) => request("DELETE", `/api/dhcp/reservations/${id}`),
  listDhcpLeases: (scopeId) => request("GET", `/api/dhcp/leases${scopeId ? "?scope_id=" + scopeId : ""}`),
  deleteDhcpLease: (id) => request("DELETE", `/api/dhcp/leases/${id}`),
  dhcpOptionCatalog: (family) => request("GET", `/api/dhcp/option-catalog?family=${family || "v4"}`),
};
