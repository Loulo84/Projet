// src/api.js — client HTTP avec refresh + open banking + USDC watcher (avec fallbacks billing)
import axios from "axios";

/** Base URL **/
const RAW = (import.meta.env.VITE_API_URL ?? "").trim();
const CLEAN = RAW.replace(/\/+$/, "");
export const API_PREFIX = CLEAN || "/api";

/** Axios instance **/
const http = axios.create({
  baseURL: API_PREFIX,
  withCredentials: true,
  headers: { "Content-Type": "application/json" },
});

/** 401 => refresh ; secours auto-compte dev (local) **/
const DEV_EMAIL = "dev@local";
const DEV_PASSWORD = "devpass1234";
const DEV_NAME = "Dev";
const DEV_COMPANY = "Local";

let refreshing = null;
http.interceptors.response.use(
  (r) => r,
  async (err) => {
    const cfg = err?.config || {};
    const status = err?.response?.status;

    if (status === 401) {
      // 1) tente /auth/refresh (une seule fois par requête)
      if (!cfg.__didRefresh) {
        try {
          refreshing =
            refreshing ||
            http.post("/auth/refresh").finally(() => (refreshing = null));
          await refreshing;
          cfg.__didRefresh = true;
          return http(cfg);
        } catch {
          /* passe au secours */
        }
      }
      // 2) secours dev local (une fois max)
      if (!cfg.__didAutoDev) {
        try {
          try {
            await http.post("/signup", {
              email: DEV_EMAIL,
              password: DEV_PASSWORD,
              name: DEV_NAME,
              company: DEV_COMPANY,
              remember: true,
            });
          } catch {}
          await http.post("/login", {
            email: DEV_EMAIL,
            password: DEV_PASSWORD,
            remember: true,
          });
          cfg.__didAutoDev = true;
          return http(cfg);
        } catch {}
      }
    }
    throw err;
  }
);

/** helpers **/
function toFD(obj) {
  const fd = new FormData();
  Object.entries(obj || {}).forEach(([k, v]) => {
    if (v != null) (Array.isArray(v) ? v : [v]).forEach((it) => fd.append(k, it));
  });
  return fd;
}

// Fallbacks: tente plusieurs chemins (utile pour /billing/* ou /stripe/*)
async function tryPaths(method, paths, { data, params, headers } = {}, defaultValue = undefined) {
  let lastErr;
  for (const p of paths) {
    try {
      const res = await http.request({ method, url: p, data, params, headers });
      return res.data;
    } catch (e) {
      lastErr = e;
      const status = e?.response?.status;
      // si 404, on tente la suite; pour autres erreurs on arrête
      if (status !== 404) throw e;
    }
  }
  if (defaultValue !== undefined) return defaultValue;
  throw lastErr;
}
const getTry  = (paths, opts, def) => tryPaths("get",    paths, opts, def);
const postTry = (paths, data, opts, def) => tryPaths("post",   paths, { ...(opts||{}), data }, def);
const delTry  = (paths, data, opts, def) => tryPaths("delete", paths, { ...(opts||{}), data }, def);

/** API **/
export const api = {
  http,

  // ------------ Auth ------------
  async signup({ email, password, name, company, remember = true }) {
    await http.post("/signup", { email, password, name, company, remember });
  },
  async login({ email, password, remember = true }) {
    await http.post("/login", { email, password, remember });
  },
  async logout() {
    await http.post("/logout");
  },
  async me() {
    const { data } = await http.get("/me");
    return data;
  },

  // ----- Orgs / Members / API keys -----
  async orgList() {
    const { data } = await http.get("/orgs");
    return data;
  },
  async memberList() {
    const { data } = await http.get("/members");
    return data;
  },
  async memberAdd(email, role) {
    const { data } = await http.post("/members", { email, role });
    return data;
  },
  async memberRemove(userId) {
    const { data } = await http.delete(`/members/${userId}`);
    return data;
  },
  async apiKeysList() {
    const { data } = await http.get("/api-keys");
    return data;
  },
  async apiKeysCreate(name) {
    const { data } = await http.post("/api-keys", { name });
    return data;
  },
  async apiKeysDelete(id) {
    const { data } = await http.delete(`/api-keys/${id}`);
    return data;
  },

  // -------- Properties / Tenants --------
  async listProperties(include_archived = false) {
    const { data } = await http.get("/properties", {
      params: { include_archived: include_archived ? 1 : 0 },
    });
    return data;
  },
  async addProperty(name) {
    const { data } = await http.post("/properties", { name });
    return data;
  },
  async deleteProperty(id, password) {
    const { data } = await http.delete(`/properties/${id}`, {
      data: { password },
    });
    return data;
  },
  async restoreProperty(id) {
    const { data } = await http.post(`/properties/${id}/restore`);
    return data;
  },

  async listTenants({ include_archived = false, property_id = null } = {}) {
    const qs = new URLSearchParams();
    if (include_archived) qs.set("include_archived", "1");
    if (property_id) qs.set("property_id", String(property_id));
    const { data } = await http.get(`/tenants?${qs.toString()}`);
    return data;
  },
  async addTenant(property_id, name, unit = "") {
    const { data } = await http.post("/tenants", { property_id, name, unit });
    return data;
  },
  async updateTenant(id, body) {
    const { data } = await http.post(`/tenants/${id}`, body);
    return data;
  },
  async deleteTenant(id, password) {
    const { data } = await http.delete(`/tenants/${id}`, {
      data: { password },
    });
    return data;
  },
  async restoreTenant(id) {
    const { data } = await http.post(`/tenants/${id}/restore`);
    return data;
  },
  async uploadTenantLease(id, file) {
    const fd = toFD({ file });
    const { data } = await http.post(`/tenants/${id}/lease`, fd, {
      headers: { "Content-Type": "multipart/form-data" },
    });
    return data;
  },
  async uploadTenantFile(id, file, label = "") {
    const fd = new FormData();
    fd.append("file", file);
    fd.append("label", label);
    const { data } = await http.post(`/tenants/${id}/files`, fd, {
      headers: { "Content-Type": "multipart/form-data" },
    });
    return data;
  },
  async deleteTenantFile(tid, fid) {
    const { data } = await http.delete(`/tenants/${tid}/files/${fid}`);
    return data;
  },

  // ---- Invoices / Dashboard / Audit ----
  async addInvoiceEUR(tenant_id, expected_eur_cents, due_date) {
    const { data } = await http.post("/invoices", {
      tenant_id,
      currency: "EUR",
      expected_eur_cents,
      due_date,
    });
    return data;
  },
  async addInvoiceUSDC(tenant_id, amount_usdc_micro, due_date) {
    const { data } = await http.post("/invoices", {
      tenant_id,
      currency: "USDC",
      amount_usdc: amount_usdc_micro / 1_000_000,
      due_date,
    });
    return data;
  },
  async listInvoices() {
    const { data } = await http.get("/invoices");
    return data;
  },
  receiptPdfUrl(id) {
    return `${API_PREFIX}/invoices/${id}/receipt.pdf`;
  },
  async dashboard(include_archived = false) {
    const { data } = await http.get("/dashboard", {
      params: { include_archived: include_archived ? 1 : 0 },
    });
    return data;
  },
  async auditList(limit = 200, user_id = null) {
    const { data } = await http.get("/audit", {
      params: { limit, ...(user_id ? { user_id } : {}) },
    });
    return data;
  },

  // --------------- Banque ---------------
  async bankList() {
    const { data } = await http.get("/payments/bank");
    return data;
  },
  async bankImportCSV(file) {
    const fd = new FormData();
    fd.append("file", file);
    const { data } = await http.post("/payments/bank/import", fd, {
      headers: { "Content-Type": "multipart/form-data" },
    });
    return data;
  },
  // compatible /payments/bank/auto-match ET /payments/auto-match
  async bankAutoMatch() {
    return await postTry(
      ["/payments/bank/auto-match", "/payments/auto-match"],
      {}
    );
  },
  // compatible /payments/bank/reconcile ET /payments/reconcile
  async bankReconcile(tx_id, invoice_id) {
    // le back "générique" attend { transaction_id }, l’autre { tx_id }
    try {
      return await postTry(["/payments/bank/reconcile"], { tx_id, invoice_id });
    } catch (e) {
      return await postTry(["/payments/reconcile"], { transaction_id: tx_id, invoice_id });
    }
  },

  // ------ Open banking (mock par défaut) ------
  async bankLinkToken() {
    const { data } = await http.post("/bank/link-token");
    return data;
  },
  async bankExchange(public_token, provider) {
    const { data } = await http.post("/bank/exchange", {
      public_token,
      provider,
    });
    return data;
  },
  async bankSync() {
    const { data } = await http.post("/bank/sync");
    return data;
  },

  // --------------- Crypto (USDC) ---------------
  async cryptoList() {
    const { data } = await http.get("/payments/crypto");
    return data;
  },
  async cryptoIngest({ network = "base", tx_hash = "", amount_usdc, reference = "" }) {
    const { data } = await http.post("/crypto/ingest", {
      network,
      tx_hash,
      amount_usdc,
      reference,
    });
    return data;
  },
  // compatible /crypto/auto-match ET /payments/crypto/auto-match
  async cryptoAutoMatch() {
    return await postTry(["/crypto/auto-match", "/payments/crypto/auto-match"], {});
  },
  async cryptoReconcile(payment_id, invoice_id) {
    const { data } = await http.post("/crypto/reconcile", {
      payment_id,
      invoice_id,
    });
    return data;
  },

  // ---- Settings / Exports / Billing ----
  async setDeletePassword(password) {
    const { data } = await http.post("/settings/delete-password", { password });
    return data;
  },
  rgpdExportUrl() {
    return `${API_PREFIX}/security/rgpd-export`;
  },
  async rgpdDelete() {
    const { data } = await http.post("/security/rgpd-delete");
    return data;
  },
  fecUrl(year) {
    return `${API_PREFIX}/exports/fec?year=${encodeURIComponent(year)}`;
  },
  downloadBackupUrl() {
    return `${API_PREFIX}/backup/download`;
  },

  // Billing (essaie /billing/* puis /stripe/*, pour éviter 404)
  async createCheckoutSession(plan) {
    return await postTry(
      ["/billing/checkout", "/stripe/checkout"],
      { plan }
    );
  },
  async createBillingPortal() {
    return await postTry(
      ["/billing/portal", "/stripe/portal"],
      {}
    );
  },
  async billingInvoices() {
    return await getTry(
      ["/billing/invoices", "/stripe/invoices"],
      {},
      [] // défaut : liste vide si endpoint absent
    );
  },

  // ---- Media (landing) ----
  async mediaList() {
    const { data } = await http.get("/site-media");
    return data;
  },
  async mediaUpload(files) {
    const fd = new FormData();
    [...files].slice(0, 12).forEach((f) => fd.append("files", f));
    const { data } = await http.post("/site-media", fd, {
      headers: { "Content-Type": "multipart/form-data" },
    });
    return data;
  },
  async mediaDelete(id) {
    const { data } = await http.delete(`/site-media/${id}`);
    return data;
  },

  // --------------- Sensitive password ---------------
  async sensitiveStatus() {
    const { data } = await http.get("/security/sensitive-password/status");
    return data;
  },
  async sensitiveSet(password, old_password) {
    const body = old_password ? { password, old_password } : { password };
    const { data } = await http.post("/security/sensitive-password", body);
    return data;
  },
  async sensitiveReset(account_password, password) {
    const { data } = await http.post("/security/sensitive-password/reset", {
      account_password,
      password,
    });
    return data;
  },

  // ---- Step-up + actions "cash" (ajout minimal) ----
  async stepUpSensitive(password) {
    const { data } = await http.post("/auth/step-up-sensitive", { password });
    return data; // { stepUpToken, exp }
  },
  async cashMark(invoice_id, stepUpToken) {
    const { data } = await http.post(
      "/payments/cash/mark",
      { invoice_id },
      stepUpToken ? { headers: { Authorization: `Bearer ${stepUpToken}` } } : {}
    );
    return data;
  },
  async cashUnmark(invoice_id, stepUpToken) {
    const { data } = await http.post(
      "/payments/cash/unmark",
      { invoice_id },
      stepUpToken ? { headers: { Authorization: `Bearer ${stepUpToken}` } } : {}
    );
    return data;
  },
};

export default api;
