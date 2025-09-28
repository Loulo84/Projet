// C:\Projet\src\api-sensible.js
const RAW = (import.meta.env.VITE_API_URL || "").trim();
const BASE = RAW
  ? (RAW.replace(/\/+$/,"").endsWith("/api") ? RAW.replace(/\/+$/,"") : `${RAW.replace(/\/+$/,"")}/api`)
  : "http://127.0.0.1:4000/api";

async function http(path, { method="GET", body, headers } = {}) {
  const res = await fetch(`${BASE}${path}`, {
    method,
    credentials: "include",
    headers: {
      ...(body && typeof body === "object" ? { "Content-Type": "application/json" } : {}),
      ...(headers || {}),
    },
    body: body && typeof body === "object" ? JSON.stringify(body) : body
  });
  const ct = res.headers.get("content-type") || "";
  const data = ct.includes("application/json") ? await res.json() : await res.text();
  if (!res.ok) throw { status: res.status, data };
  return data;
}

export const sensitiveApi = {
  status() { return http("/security/sensitive-password/status"); },
  set(newPwd, oldPwd) {
    return http("/security/sensitive-password", {
      method:"POST",
      body: oldPwd ? { password:newPwd, old_password:oldPwd } : { password:newPwd }
    });
  },
  reset(accountPwd, newPwd) {
    return http("/security/sensitive-password/reset", {
      method:"POST",
      body:{ account_password:accountPwd, password:newPwd }
    });
  },
  stepUp(pwd) {
    return http("/auth/step-up-sensitive", { method:"POST", body:{ password:pwd } });
  },
  cashMark(invoiceId, stepUpToken) {
    return http("/payments/cash/mark", {
      method:"POST",
      headers: stepUpToken ? { Authorization:`Bearer ${stepUpToken}` } : undefined,
      body:{ invoice_id:invoiceId }
    });
  },
  cashUnmark(invoiceId, stepUpToken) {
    return http("/payments/cash/unmark", {
      method:"POST",
      headers: stepUpToken ? { Authorization:`Bearer ${stepUpToken}` } : undefined,
      body:{ invoice_id:invoiceId }
    });
  },
};
