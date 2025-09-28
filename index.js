// C:\Projet\index.js
/**
 * RentChain — API serveur
 * - Auth JWT (cookies httpOnly)
 * - SQLite (better-sqlite3)
 * - Stripe réel : Checkout, Billing Portal, Webhooks
 * - Orgs + rôles (RBAC)
 * - API Keys (lecture)
 * - Export sauvegarde JSON
 * - Quotas par plan (FREE/PRO/AGENCY)
 * - Quittances PDF
 * - Paiements:
 *   - Bancaire: import CSV (relevés), auto-match, réconciliation -> marque facture "Payé"
 *   - Crypto: ingestion webhook/simulation, appariement, marque facture "Payé"
 *
 * ENV:
 *  PORT, CLIENT_ORIGIN, JWT_SECRET, DB_PATH, FILES_DIR, SITE_URL
 *  STRIPE_SECRET_KEY, STRIPE_WEBHOOK_SECRET, STRIPE_PRICE_PRO, STRIPE_PRICE_AGENCY
 */

const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const path = require("path");
const fs = require("fs");
const multer = require("multer");
const Database = require("better-sqlite3");
const PDFDocument = require("pdfkit");
const crypto = require("crypto");
require("dotenv").config();

// ---------- Config ------------------------------------------------------------
const SECRET = process.env.JWT_SECRET || "change_this_secret_in_prod";
const PORT = process.env.PORT ? Number(process.env.PORT) : 4000;
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "rentchain.db");
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || "http://localhost:5173";
const FILES_DIR = process.env.FILES_DIR || path.join(__dirname, "uploads");
const SITE_URL = process.env.SITE_URL || "http://localhost:5173";

// Stripe
const STRIPE_KEY = process.env.STRIPE_SECRET_KEY || "";
const STRIPE_WEBHOOK_SECRET = process.env.STRIPE_WEBHOOK_SECRET || "";
const STRIPE_PRICE_PRO = process.env.STRIPE_PRICE_PRO || "";
const STRIPE_PRICE_AGENCY = process.env.STRIPE_PRICE_AGENCY || "";
const stripe = STRIPE_KEY ? require("stripe")(STRIPE_KEY) : null;

// ---------- FS init -----------------------------------------------------------
if (!fs.existsSync(FILES_DIR)) fs.mkdirSync(FILES_DIR, { recursive: true });

// ---------- DB init -----------------------------------------------------------
const db = new Database(DB_PATH);

// -- Utilisateurs / Orgs / Rôles ----------------------------------------------
db.prepare(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    name TEXT,
    company TEXT,
    password_hash TEXT,
    created_at TEXT,
    stripe_customer_id TEXT,
    subscription_status TEXT,
    plan TEXT,
    quota_json TEXT
  )
`).run();

db.prepare(`
  CREATE TABLE IF NOT EXISTS organizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    created_at TEXT NOT NULL
  )
`).run();

db.prepare(`
  CREATE TABLE IF NOT EXISTS org_members (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    role TEXT NOT NULL, -- OWNER, ADMIN, AGENT, ACCOUNTANT, VIEWER
    UNIQUE(org_id, user_id)
  )
`).run();

db.prepare(`
  CREATE TABLE IF NOT EXISTS api_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    last_used_at TEXT
  )
`).run();

// -- settings globaux ----------------------------------------------------------
db.prepare(`
  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
  )
`).run();

// >>> AJOUT : garantir la clé du mot de passe sensible
try {
  const row = db.prepare("SELECT value FROM settings WHERE key='sensitive_password_hash'").get();
  if (!row) db.prepare("INSERT INTO settings(key,value) VALUES('sensitive_password_hash','')").run();
} catch {}

// -- Données métier ------------------------------------------------------------
db.prepare(`
  CREATE TABLE IF NOT EXISTS properties (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER,
    user_id INTEGER,
    name TEXT NOT NULL,
    deleted_at TEXT
  )
`).run();

db.prepare(`
  CREATE TABLE IF NOT EXISTS tenants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER,
    user_id INTEGER,
    property_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    unit TEXT,
    address TEXT,
    lease_path TEXT,
    lease_uploaded_at TEXT,
    deleted_at TEXT
  )
`).run();

db.prepare(`
  CREATE TABLE IF NOT EXISTS tenant_files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER,
    user_id INTEGER,
    tenant_id INTEGER NOT NULL,
    label TEXT,
    file_path TEXT,
    uploaded_at TEXT
  )
`).run();

db.prepare(`
  CREATE TABLE IF NOT EXISTS invoices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER,
    user_id INTEGER,
    tenant_id INTEGER NOT NULL,
    currency TEXT NOT NULL, -- EUR|USDC
    expected_eur_cents INTEGER,
    amount_usdc_micro INTEGER,
    status TEXT NOT NULL, -- En attente|Payé|Partiel
    due_date TEXT,
    paid_at TEXT,
    receipt_note TEXT
  )
`).run();

// >>> AJOUT : colonne indicative pour marquage cash (si absente)
try { db.prepare("ALTER TABLE invoices ADD COLUMN paid_via_cash INTEGER DEFAULT 0").run(); } catch {}

db.prepare(`
  CREATE TABLE IF NOT EXISTS subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    stripe_subscription_id TEXT,
    plan TEXT,
    status TEXT,
    current_period_end INTEGER,
    created_at TEXT,
    updated_at TEXT
  )
`).run();

db.prepare(`
  CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    ip TEXT,
    ua TEXT,
    meta TEXT,
    created_at TEXT NOT NULL
  )
`).run();

/** Paiements bancaires importés (CSV)
 *  amount_eur_cents: entier signé (crédit positif, débit négatif)
 */
db.prepare(`
  CREATE TABLE IF NOT EXISTS bank_transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    tx_date TEXT NOT NULL,
    amount_eur_cents INTEGER NOT NULL,
    counterparty TEXT,
    reference TEXT,
    raw_json TEXT,
    matched_invoice_id INTEGER,
    created_at TEXT NOT NULL
  )
`).run();

/** Paiements crypto reçus (ex. USDC)
 *  status: received|matched|ignored
 */
db.prepare(`
  CREATE TABLE IF NOT EXISTS crypto_payments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER NOT NULL,
    network TEXT,
    tx_hash TEXT,
    currency TEXT, -- USDC
    amount_usdc_micro INTEGER,
    reference TEXT, -- libre
    matched_invoice_id INTEGER,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL
  )
`).run();

// index perfs
db.prepare(`CREATE INDEX IF NOT EXISTS idx_props_org ON properties(org_id)`).run();
db.prepare(`CREATE INDEX IF NOT EXISTS idx_tenants_org ON tenants(org_id)`).run();
db.prepare(`CREATE INDEX IF NOT EXISTS idx_tfiles_org ON tenant_files(org_id)`).run();
db.prepare(`CREATE INDEX IF NOT EXISTS idx_invoices_org ON invoices(org_id)`).run();
db.prepare(`CREATE INDEX IF NOT EXISTS idx_bank_org ON bank_transactions(org_id)`).run();
db.prepare(`CREATE INDEX IF NOT EXISTS idx_crypto_org ON crypto_payments(org_id)`).run();

// ---------- App / CORS / Body parsers ----------------------------------------
const app = express();
const corsOptions = {
  origin: CLIENT_ORIGIN,
  credentials: true,
  methods: "GET,POST,PUT,PATCH,DELETE,OPTIONS",
  allowedHeaders: "Content-Type, Authorization, X-API-Key, X-Org"
};
app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

// Webhook Stripe = body brut
app.use((req, res, next) => {
  if (req.originalUrl === "/api/stripe/webhook") return next();
  express.json({ limit: "4mb" })(req, res, next);
});

app.use(cookieParser());
app.use("/files", express.static(FILES_DIR));
const upload = multer({ dest: FILES_DIR });

// ---------- Helpers -----------------------------------------------------------
function signToken(payload) {
  return jwt.sign(payload, SECRET, { expiresIn: "7d" });
}
function authMiddleware(req, res, next) {
  try {
    const token =
      req.cookies?.token ||
      (req.headers.authorization && req.headers.authorization.split(" ")[1]);
    if (!token) return res.status(401).json({ error: "Non autorisé" });
    req.user = jwt.verify(token, SECRET);
    next();
  } catch {
    return res.status(401).json({ error: "Token invalide" });
  }
}
function logAudit(userId, action, req, metaObj) {
  const ip =
    req.headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    req.socket?.remoteAddress ||
    "";
  const ua = req.headers["user-agent"] || "";
  const meta = metaObj ? JSON.stringify(metaObj) : null;
  db.prepare(
    "INSERT INTO audit_logs (user_id, action, ip, ua, meta, created_at) VALUES (?, ?, ?, ?, ?, ?)"
  ).run(userId || null, action, ip, ua, meta, new Date().toISOString());
}

const DEFAULT_QUOTAS = {
  FREE:   { properties: 1, tenants: 5, storageMB: 20 },
  PRO:    { properties: 10, tenants: 200, storageMB: 1000 },
  AGENCY: { properties: 100, tenants: 5000, storageMB: 10000 }
};
function quotasFor(plan) {
  return DEFAULT_QUOTAS[(plan || "FREE").toUpperCase()] || DEFAULT_QUOTAS.FREE;
}
function ensureUserQuotasRow(u) {
  if (!u.quota_json) {
    const q = JSON.stringify(quotasFor(u.plan || "FREE"));
    db.prepare("UPDATE users SET quota_json=? WHERE id=?").run(q, u.id);
    u.quota_json = q;
  }
  try { return JSON.parse(u.quota_json); } catch { return quotasFor(u.plan || "FREE"); }
}

const ROLES = ["OWNER", "ADMIN", "AGENT", "ACCOUNTANT", "VIEWER"];
function requireRole(roleList) {
  return (req, res, next) => {
    const mem = currentMembership(req);
    if (!mem) return res.status(403).json({ error: "Organisation introuvable" });
    if (!roleList.includes(mem.role)) return res.status(403).json({ error: "Accès interdit" });
    next();
  };
}
function currentMembership(req) {
  const userId = req.user?.id;
  if (!userId) return null;
  const wantedOrg = req.headers["x-org"] ? Number(req.headers["x-org"]) : null;
  if (wantedOrg) {
    const m = db.prepare("SELECT * FROM org_members WHERE user_id=? AND org_id=?").get(userId, wantedOrg);
    if (m) return m;
    return null;
  }
  const m = db.prepare("SELECT * FROM org_members WHERE user_id=? ORDER BY id ASC").get(userId);
  return m || null;
}
function ensureOrgOnSignup(userId, orgName) {
  const has = db.prepare("SELECT id, org_id FROM org_members WHERE user_id=?").get(userId);
  if (has) return has.org_id;
  const now = new Date().toISOString();
  const info = db.prepare("INSERT INTO organizations (name, created_at) VALUES (?, ?)").run(orgName || "Mon agence", now);
  db.prepare("INSERT INTO org_members (org_id, user_id, role) VALUES (?, ?, 'OWNER')").run(info.lastInsertRowid, userId);
  return info.lastInsertRowid;
}

// API keys --------------------------------------------------------------------
function hashToken(token) {
  return crypto.createHash("sha256").update(token).digest("hex");
}
function apiKeyMiddleware(req, res, next) {
  const key = req.headers["x-api-key"];
  if (!key) return next();
  const orgHeader = req.headers["x-org"];
  const row = db.prepare("SELECT * FROM api_tokens WHERE token_hash=?").get(hashToken(String(key)));
  if (!row) return res.status(401).json({ error: "Clé API invalide" });
  if (orgHeader && Number(orgHeader) !== row.org_id) {
    return res.status(403).json({ error: "Clé API non autorisée pour cette organisation" });
  }
  req.apiKey = { org_id: row.org_id, token_id: row.id };
  db.prepare("UPDATE api_tokens SET last_used_at=? WHERE id=?").run(new Date().toISOString(), row.id);
  next();
}
app.use(apiKeyMiddleware);

// ---------- Health ------------------------------------------------------------
app.get("/api/health", (_req, res) => res.json({ ok: true }));

// ---------- AUTH --------------------------------------------------------------
app.post("/api/signup", async (req, res) => {
  try {
    const { email, password, name, company } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: "Email et mot de passe requis" });
    const exists = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
    if (exists) return res.status(409).json({ error: "Email déjà utilisé" });

    const hash = await bcrypt.hash(password, 10);
    const now = new Date().toISOString();

    let stripeCustomerId = null;
    if (stripe) {
      const customer = await stripe.customers.create({
        email,
        name: company || name || email,
        metadata: { app: "RentChain" },
      });
      stripeCustomerId = customer.id;
    }

    const info = db.prepare(`
      INSERT INTO users (email, name, company, password_hash, created_at, plan, subscription_status, stripe_customer_id, quota_json)
      VALUES (?, ?, ?, ?, ?, 'FREE', 'inactive', ?, ?)
    `).run(email, name || "", company || "", hash, now, stripeCustomerId, JSON.stringify(quotasFor("FREE")));

    const uid = info.lastInsertRowid;
    const orgId = ensureOrgOnSignup(uid, company || "Mon agence");

    const token = signToken({ id: uid, email });
    res.cookie("token", token, { httpOnly: true, sameSite: "lax", maxAge: 7 * 24 * 3600 * 1000 });
    logAudit(uid, "signup", req, { email, orgId });
    return res.json({ user: { id: uid, email, name: name || "", company: company || "", created_at: now }, org_id: orgId });
  } catch (e) {
    console.error(e); return res.status(500).json({ error: "Erreur interne" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) return res.status(400).json({ error: "Email et mot de passe requis" });
    const u = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
    if (!u) { logAudit(null, "login_failed", req, { email }); return res.status(401).json({ error: "Identifiants invalides" }); }
    const ok = await bcrypt.compare(password, u.password_hash);
    if (!ok) { logAudit(u.id, "login_failed", req); return res.status(401).json({ error: "Identifiants invalides" }); }

    const token = signToken({ id: u.id, email: u.email });
    res.cookie("token", token, { httpOnly: true, sameSite: "lax", maxAge: 7 * 24 * 3600 * 1000 });
    logAudit(u.id, "login", req);
    return res.json({ user: { id: u.id, email: u.email, name: u.name, company: u.company, created_at: u.created_at } });
  } catch (e) {
    console.error(e); return res.status(500).json({ error: "Erreur interne" });
  }
});

app.post("/api/logout", (req, res) => { res.clearCookie("token"); res.json({ ok: true }); });

app.get("/api/me", authMiddleware, (req, res) => {
  const u = db.prepare("SELECT id, email, name, company, created_at, plan, subscription_status, stripe_customer_id, quota_json FROM users WHERE id = ?").get(req.user.id);
  if (!u) return res.status(404).json({ error: "Utilisateur introuvable" });
  const mem = currentMembership(req);
  const orgs = db.prepare(`
    SELECT om.org_id AS id, o.name, om.role
    FROM org_members om JOIN organizations o ON o.id = om.org_id
    WHERE om.user_id = ?
    ORDER BY o.id ASC
  `).all(req.user.id);
  res.json({ ...u, quotas: ensureUserQuotasRow(u), org_memberships: orgs, current_org_id: mem?.org_id || null });
});

// ---------- Orgs / Members / API keys / Backup -------------------------------
app.get("/api/orgs", authMiddleware, (req, res) => {
  const list = db.prepare(`
    SELECT o.id, o.name, om.role
    FROM org_members om JOIN organizations o ON o.id = om.org_id
    WHERE om.user_id = ?
    ORDER BY o.id ASC
  `).all(req.user.id);
  res.json(list);
});
app.post("/api/orgs", authMiddleware, requireRole(["OWNER","ADMIN"]), (req, res) => {
  const { name } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error: "Nom requis" });
  const now = new Date().toISOString();
  const info = db.prepare("INSERT INTO organizations (name, created_at) VALUES (?, ?)").run(name.trim(), now);
  db.prepare("INSERT INTO org_members (org_id, user_id, role) VALUES (?, ?, 'OWNER')").run(info.lastInsertRowid, req.user.id);
  logAudit(req.user.id, "org_create", req, { org_id: info.lastInsertRowid });
  res.json({ id: info.lastInsertRowid, name });
});
app.get("/api/members", authMiddleware, requireRole(["OWNER","ADMIN"]), (req, res) => {
  const mem = currentMembership(req);
  const rows = db.prepare(`
    SELECT om.user_id, u.email, u.name, om.role
    FROM org_members om JOIN users u ON u.id = om.user_id
    WHERE om.org_id = ?
    ORDER BY om.user_id ASC
  `).all(mem.org_id);
  res.json(rows);
});
app.post("/api/members", authMiddleware, requireRole(["OWNER","ADMIN"]), (req, res) => {
  const mem = currentMembership(req);
  const { email, role } = req.body || {};
  if (!email || !role || !ROLES.includes(role)) return res.status(400).json({ error: "Paramètres invalides" });
  const u = db.prepare("SELECT id FROM users WHERE email=?").get(email);
  if (!u) return res.status(404).json({ error: "Utilisateur introuvable" });
  db.prepare("INSERT OR IGNORE INTO org_members (org_id, user_id, role) VALUES (?, ?, ?)").run(mem.org_id, u.id, role);
  db.prepare("UPDATE org_members SET role=? WHERE org_id=? AND user_id=?").run(role, mem.org_id, u.id);
  logAudit(req.user.id, "member_upsert", req, { org_id: mem.org_id, target_user: u.id, role });
  res.json({ ok: true });
});
app.delete("/api/members/:userId", authMiddleware, requireRole(["OWNER","ADMIN"]), (req, res) => {
  const mem = currentMembership(req);
  const target = Number(req.params.userId);
  db.prepare("DELETE FROM org_members WHERE org_id=? AND user_id=?").run(mem.org_id, target);
  logAudit(req.user.id, "member_delete", req, { org_id: mem.org_id, target });
  res.json({ ok: true });
});
app.get("/api/api-keys", authMiddleware, requireRole(["OWNER","ADMIN"]), (req, res) => {
  const mem = currentMembership(req);
  const rows = db.prepare("SELECT id, name, created_at, last_used_at FROM api_tokens WHERE org_id=? ORDER BY id DESC").all(mem.org_id);
  res.json(rows);
});
app.post("/api/api-keys", authMiddleware, requireRole(["OWNER","ADMIN"]), (req, res) => {
  const mem = currentMembership(req);
  const { name } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error: "Nom requis" });
  const token = crypto.randomBytes(24).toString("base64url");
  const now = new Date().toISOString();
  db.prepare("INSERT INTO api_tokens (org_id, name, token_hash, created_at) VALUES (?, ?, ?, ?)")
    .run(mem.org_id, name.trim(), hashToken(token), now);
  logAudit(req.user.id, "api_key_create", req, { org_id: mem.org_id, name });
  res.json({ token });
});
app.delete("/api/api-keys/:id", authMiddleware, requireRole(["OWNER","ADMIN"]), (req, res) => {
  const mem = currentMembership(req);
  db.prepare("DELETE FROM api_tokens WHERE id=? AND org_id=?").run(Number(req.params.id), mem.org_id);
  logAudit(req.user.id, "api_key_delete", req, { org_id: mem.org_id, id: Number(req.params.id) });
  res.json({ ok: true });
});
app.get("/api/backup", authMiddleware, requireRole(["OWNER","ADMIN"]), (req, res) => {
  const mem = currentMembership(req);
  const orgId = mem.org_id;
  const data = {
    org: db.prepare("SELECT * FROM organizations WHERE id=?").get(orgId),
    members: db.prepare("SELECT * FROM org_members WHERE org_id=?").all(orgId),
    properties: db.prepare("SELECT * FROM properties WHERE org_id=?").all(orgId),
    tenants: db.prepare("SELECT * FROM tenants WHERE org_id=?").all(orgId),
    tenant_files: db.prepare("SELECT id, tenant_id, label, file_path, uploaded_at FROM tenant_files WHERE org_id=?").all(orgId),
    invoices: db.prepare("SELECT * FROM invoices WHERE org_id=?").all(orgId),
    subscriptions: db.prepare(`
      SELECT s.* FROM subscriptions s
      JOIN users u ON u.id = s.user_id
      JOIN org_members om ON om.user_id = u.id
      WHERE om.org_id=?`).all(orgId),
    bank_transactions: db.prepare("SELECT * FROM bank_transactions WHERE org_id=?").all(orgId),
    crypto_payments: db.prepare("SELECT * FROM crypto_payments WHERE org_id=?").all(orgId),
  };
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Content-Disposition", `attachment; filename="backup-org-${orgId}.json"`);
  res.end(JSON.stringify(data, null, 2));
});

// ---------- Settings (delete password) ---------------------------------------
app.post("/api/settings/delete-password", authMiddleware, (req, res) => {
  const { password } = req.body || {};
  if (!password || password.length < 6) return res.status(400).json({ error: "Mot de passe trop court" });
  const hash = bcrypt.hashSync(password, 10);
  db.prepare("INSERT INTO settings (key, value) VALUES ('delete_password_hash', ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value").run(hash);
  logAudit(req.user.id, "set_delete_password", req);
  res.json({ ok: true });
});
function requireDeletePassword(pwd) {
  const row = db.prepare("SELECT value FROM settings WHERE key='delete_password_hash'").get();
  if (!row) return false;
  return bcrypt.compareSync(String(pwd || ""), row.value);
}

// ---------- Sélecteur d’org --------------------------------------------------
function resolveOrgId(req) {
  if (req.apiKey) return req.apiKey.org_id;
  const mem = currentMembership(req);
  return mem?.org_id || null;
}

// ---------- PROPERTIES -------------------------------------------------------
app.get("/api/properties", (req, res) => {
  if (!req.apiKey && !req.user) return authMiddleware(req, res, () => app._router.handle(req, res));
  const orgId = resolveOrgId(req);
  if (!orgId) return res.status(403).json({ error: "Organisation requise" });
  const include = req.query.include_archived === "1";
  const rows = db.prepare(`SELECT * FROM properties WHERE org_id = ? ${include ? "" : "AND deleted_at IS NULL"} ORDER BY id DESC`).all(orgId);
  res.json(rows);
});
app.post("/api/properties", authMiddleware, requireRole(["OWNER","ADMIN","AGENT"]), (req, res) => {
  const orgId = resolveOrgId(req);
  const u = db.prepare("SELECT * FROM users WHERE id=?").get(req.user.id);
  const quotas = ensureUserQuotasRow(u);
  const count = db.prepare("SELECT COUNT(*) AS c FROM properties WHERE org_id = ? AND deleted_at IS NULL").get(orgId).c;
  if (count >= (quotas.properties||0)) return res.status(403).json({ error: "Quota propriétés atteint." });

  const { name } = req.body || {};
  if (!name || !name.trim()) return res.status(400).json({ error: "Nom requis" });
  const info = db.prepare("INSERT INTO properties (org_id, user_id, name) VALUES (?, ?, ?)").run(orgId, req.user.id, name.trim());
  logAudit(req.user.id, "property_add", req, { id: info.lastInsertRowid, org_id: orgId });
  res.json({ id: info.lastInsertRowid, name });
});
app.delete("/api/properties/:id", authMiddleware, requireRole(["OWNER","ADMIN"]), (req, res) => {
  const orgId = resolveOrgId(req);
  const { password } = req.body || {};
  if (!requireDeletePassword(password)) return res.status(400).json({ error: "Mot de passe invalide" });
  db.prepare("UPDATE properties SET deleted_at = ? WHERE id = ? AND org_id = ?").run(new Date().toISOString(), Number(req.params.id), orgId);
  logAudit(req.user.id, "property_delete", req, { id: Number(req.params.id), org_id: orgId });
  res.json({ ok: true });
});
app.post("/api/properties/:id/restore", authMiddleware, requireRole(["OWNER","ADMIN"]), (req, res) => {
  const orgId = resolveOrgId(req);
  db.prepare("UPDATE properties SET deleted_at = NULL WHERE id = ? AND org_id = ?").run(Number(req.params.id), orgId);
  logAudit(req.user.id, "property_restore", req, { id: Number(req.params.id), org_id: orgId });
  res.json({ ok: true });
});

// ---------- TENANTS ----------------------------------------------------------
app.get("/api/tenants", (req, res) => {
  if (!req.apiKey && !req.user) return authMiddleware(req, res, () => app._router.handle(req, res));
  const orgId = resolveOrgId(req);
  if (!orgId) return res.status(403).json({ error: "Organisation requise" });
  const include = req.query.include_archived === "1";
  const whereExtra = [];
  const params = [orgId];
  if (!include) whereExtra.push("deleted_at IS NULL");
  if (req.query.property_id) { whereExtra.push("property_id = ?"); params.push(Number(req.query.property_id)); }
  const rows = db.prepare(`SELECT * FROM tenants WHERE org_id = ? ${whereExtra.length ? "AND " + whereExtra.join(" AND ") : ""} ORDER BY id DESC`).all(...params);
  res.json(rows);
});
app.post("/api/tenants", authMiddleware, requireRole(["OWNER","ADMIN","AGENT"]), (req, res) => {
  const orgId = resolveOrgId(req);
  const u = db.prepare("SELECT * FROM users WHERE id=?").get(req.user.id);
  const quotas = ensureUserQuotasRow(u);
  const count = db.prepare("SELECT COUNT(*) AS c FROM tenants WHERE org_id = ? AND deleted_at IS NULL").get(orgId).c;
  if (count >= (quotas.tenants||0)) return res.status(403).json({ error: "Quota locataires atteint." });

  const { property_id, name, unit } = req.body || {};
  if (!property_id || !name) return res.status(400).json({ error: "Champs requis" });
  const info = db.prepare("INSERT INTO tenants (org_id, user_id, property_id, name, unit) VALUES (?, ?, ?, ?, ?)").run(orgId, req.user.id, Number(property_id), name.trim(), (unit||"").trim());
  logAudit(req.user.id, "tenant_add", req, { id: info.lastInsertRowid, org_id: orgId });
  res.json({ id: info.lastInsertRowid, property_id, name, unit });
});
app.post("/api/tenants/:id", authMiddleware, requireRole(["OWNER","ADMIN","AGENT"]), (req, res) => {
  const orgId = resolveOrgId(req);
  const { name, unit, address } = req.body || {};
  db.prepare("UPDATE tenants SET name=?, unit=?, address=? WHERE id=? AND org_id=?")
    .run((name||"").trim(), (unit||"").trim(), (address||"").trim(), Number(req.params.id), orgId);
  logAudit(req.user.id, "tenant_update", req, { id: Number(req.params.id), org_id: orgId });
  res.json({ ok: true });
});
app.delete("/api/tenants/:id", authMiddleware, requireRole(["OWNER","ADMIN"]), (req, res) => {
  const orgId = resolveOrgId(req);
  const { password } = req.body || {};
  if (!requireDeletePassword(password)) return res.status(400).json({ error: "Mot de passe invalide" });
  db.prepare("UPDATE tenants SET deleted_at = ? WHERE id=? AND org_id=?").run(new Date().toISOString(), Number(req.params.id), orgId);
  logAudit(req.user.id, "tenant_delete", req, { id: Number(req.params.id), org_id: orgId });
  res.json({ ok: true });
});
app.post("/api/tenants/:id/restore", authMiddleware, requireRole(["OWNER","ADMIN"]), (req, res) => {
  const orgId = resolveOrgId(req);
  db.prepare("UPDATE tenants SET deleted_at=NULL WHERE id=? AND org_id=?").run(Number(req.params.id), orgId);
  logAudit(req.user.id, "tenant_restore", req, { id: Number(req.params.id), org_id: orgId });
  res.json({ ok: true });
});

// bail (upload)
app.post("/api/tenants/:id/lease", authMiddleware, requireRole(["OWNER","ADMIN","AGENT"]), upload.single("file"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "Fichier requis" });
  const orgId = resolveOrgId(req);
  const now = new Date().toISOString();
  db.prepare("UPDATE tenants SET lease_path=?, lease_uploaded_at=? WHERE id=? AND org_id=?")
    .run(req.file.path, now, Number(req.params.id), orgId);
  logAudit(req.user.id, "tenant_lease_upload", req, { id: Number(req.params.id), file: req.file.filename, org_id: orgId });
  res.json({ ok: true, url: `${req.protocol}://${req.get("host")}/files/${path.basename(req.file.path)}` });
});
app.delete("/api/tenants/:id/lease", authMiddleware, requireRole(["OWNER","ADMIN","AGENT"]), (req, res) => {
  const orgId = resolveOrgId(req);
  const t = db.prepare("SELECT lease_path FROM tenants WHERE id = ? AND org_id = ?").get(Number(req.params.id), orgId);
  if (t?.lease_path && fs.existsSync(t.lease_path)) { try { fs.unlinkSync(t.lease_path); } catch {} }
  db.prepare("UPDATE tenants SET lease_path=NULL, lease_uploaded_at=NULL WHERE id=? AND org_id=?").run(Number(req.params.id), orgId);
  logAudit(req.user.id, "tenant_lease_delete", req, { id: Number(req.params.id), org_id: orgId });
  res.json({ ok: true });
});

// pièces jointes
app.get("/api/tenants/:id/files", (req, res) => {
  if (!req.apiKey && !req.user) return authMiddleware(req, res, () => app._router.handle(req, res));
  const orgId = resolveOrgId(req);
  const rows = db.prepare("SELECT id, label, file_path FROM tenant_files WHERE org_id=? AND tenant_id=? ORDER BY id DESC").all(orgId, Number(req.params.id));
  res.json(rows.map(r => ({ id: r.id, label: r.label, url: `${req.protocol}://${req.get("host")}/files/${path.basename(r.file_path)}` })));
});
app.post("/api/tenants/:id/files", authMiddleware, requireRole(["OWNER","ADMIN","AGENT"]), upload.single("file"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "Fichier requis" });
  const orgId = resolveOrgId(req);
  const label = (req.body?.label || "").trim();
  const now = new Date().toISOString();
  db.prepare("INSERT INTO tenant_files (org_id, user_id, tenant_id, label, file_path, uploaded_at) VALUES (?, ?, ?, ?, ?, ?)")
    .run(orgId, req.user.id, Number(req.params.id), label, req.file.path, now);
  logAudit(req.user.id, "tenant_file_upload", req, { tenant_id: Number(req.params.id), file: req.file.filename, org_id: orgId });
  res.json({ ok: true });
});
app.delete("/api/tenants/:id/files/:fileId", authMiddleware, requireRole(["OWNER","ADMIN","AGENT"]), (req, res) => {
  const orgId = resolveOrgId(req);
  const r = db.prepare("SELECT file_path FROM tenant_files WHERE id=? AND org_id=? AND tenant_id=?").get(Number(req.params.fileId), orgId, Number(req.params.id));
  if (r?.file_path && fs.existsSync(r.file_path)) { try { fs.unlinkSync(r.file_path); } catch {} }
  db.prepare("DELETE FROM tenant_files WHERE id=? AND org_id=? AND tenant_id=?").run(Number(req.params.fileId), orgId, Number(req.params.id));
  logAudit(req.user.id, "tenant_file_delete", req, { tenant_id: Number(req.params.id), file_id: Number(req.params.fileId), org_id: orgId });
  res.json({ ok: true });
});

// ---------- INVOICES / LOYERS -----------------------------------------------
app.post("/api/invoices", authMiddleware, requireRole(["OWNER","ADMIN","AGENT","ACCOUNTANT"]), (req, res) => {
  const orgId = resolveOrgId(req);
  const { tenant_id, currency, expected_eur_cents, amount_usdc, due_date } = req.body || {};
  if (!tenant_id || !currency) return res.status(400).json({ error: "Champs requis" });
  if (currency === "EUR" && (!Number.isFinite(expected_eur_cents) || expected_eur_cents <= 0)) return res.status(400).json({ error: "Montant EUR invalide" });
  if (currency === "USDC" && (!Number.isFinite(amount_usdc) || amount_usdc <= 0)) return res.status(400).json({ error: "Montant USDC invalide" });

  const info = db.prepare(`
    INSERT INTO invoices (org_id, user_id, tenant_id, currency, expected_eur_cents, amount_usdc_micro, status, due_date)
    VALUES (?, ?, ?, ?, ?, ?, 'En attente', ?)
  `).run(
    orgId,
    req.user.id,
    Number(tenant_id),
    currency,
    currency === "EUR" ? Math.round(expected_eur_cents) : null,
    currency === "USDC" ? Math.round(amount_usdc * 1_000_000) : null,
    due_date || null
  );
  logAudit(req.user.id, "invoice_add", req, { id: info.lastInsertRowid, org_id: orgId });
  res.json({ id: info.lastInsertRowid });
});

app.get("/api/invoices", (req, res) => {
  if (!req.apiKey && !req.user) return authMiddleware(req, res, () => app._router.handle(req, res));
  const orgId = resolveOrgId(req);
  const rows = db.prepare("SELECT * FROM invoices WHERE org_id=? ORDER BY id DESC").all(orgId);
  res.json(rows.map(r => ({ ...r, amount_usdc: r.amount_usdc_micro ? r.amount_usdc_micro / 1_000_000 : null })));
});

app.get("/api/invoices/:id/receipt.pdf", (req, res) => {
  if (!req.apiKey && !req.user) return authMiddleware(req, res, () => app._router.handle(req, res));
  const orgId = resolveOrgId(req);
  const r = db.prepare(`
    SELECT i.*, t.name AS tenant_name
    FROM invoices i JOIN tenants t ON t.id = i.tenant_id
    WHERE i.id=? AND i.org_id=?
  `).get(Number(req.params.id), orgId);
  if (!r) return res.status(404).send("Not found");

  res.setHeader("Content-Type", "application/pdf");
  res.setHeader("Content-Disposition", `inline; filename="quittance-${r.id}.pdf"`);

  const doc = new PDFDocument({ size: "A4", margin: 50 });
  doc.pipe(res);
  doc.fontSize(18).text("Quittance de loyer", { align: "center" });
  doc.moveDown();
  doc.fontSize(12);
  doc.text(`Quittance #${r.id}`);
  doc.text(`Locataire : ${r.tenant_name}`);
  doc.text(`Devise : ${r.currency}`);
  if (r.currency === "EUR") doc.text(`Montant attendu : ${(r.expected_eur_cents/100).toFixed(2)} €`);
  if (r.currency === "USDC") doc.text(`Montant attendu : ${(r.amount_usdc_micro/1_000_000).toFixed(6)} USDC`);
  doc.text(`Statut : ${r.status}`);
  if (r.due_date) doc.text(`Échéance : ${r.due_date}`);
  if (r.paid_at) doc.text(`Payé le : ${r.paid_at}`);
  if (r.receipt_note) doc.text(`Note : ${r.receipt_note}`);
  doc.moveDown();
  doc.text(`Émis le ${new Date().toLocaleString("fr-FR")}`);
  doc.end();
});

// ---------- DASHBOARD ---------------------------------------------------------
app.get("/api/dashboard", (req, res) => {
  if (!req.apiKey && !req.user) return authMiddleware(req, res, () => app._router.handle(req, res));
  const orgId = resolveOrgId(req);
  const rows = db.prepare(`
    SELECT i.id, t.name AS tenant_name, i.currency, i.expected_eur_cents, i.amount_usdc_micro, i.status
    FROM invoices i JOIN tenants t ON t.id = i.tenant_id
    WHERE i.org_id = ?
    ORDER BY i.id DESC LIMIT 200
  `).all(orgId);
  res.json(rows.map(r => ({
    id: r.id,
    tenant_name: r.tenant_name,
    currency: r.currency,
    amount_eur: r.expected_eur_cents != null ? Math.round(r.expected_eur_cents)/100 : null,
    amount_usdc: r.amount_usdc_micro != null ? Math.round(r.amount_usdc_micro)/1_000_000 : null,
    status: r.status
  })));
});

// ---------- TENANTS WITH STATUS ----------------------------------------------
app.get("/api/tenants-with-status", (req, res) => {
  if (!req.apiKey && !req.user) return authMiddleware(req, res, () => app._router.handle(req, res));
  const orgId = resolveOrgId(req);
  const include = req.query.include_archived === "1";
  const tenants = db.prepare(`
    SELECT * FROM tenants WHERE org_id=? ${include ? "" : "AND deleted_at IS NULL"} ORDER BY id DESC
  `).all(orgId);

  const pendings = db.prepare("SELECT tenant_id, COUNT(*) AS c FROM invoices WHERE org_id=? AND status!='Payé' GROUP BY tenant_id").all(orgId);
  const map = new Map(pendings.map(p => [p.tenant_id, p.c]));
  const baseUrl = (req.protocol + "://" + req.get("host") + "/files/");

  res.json(tenants.map(t => ({
    id: t.id,
    name: t.name,
    unit: t.unit,
    address: t.address,
    property_id: t.property_id,
    deleted_at: t.deleted_at,
    lease_url: t.lease_path ? (baseUrl + path.basename(t.lease_path)) : null,
    lease_uploaded_at: t.lease_uploaded_at,
    pending_invoices: map.get(t.id) || 0,
    up_to_date: (map.get(t.id) || 0) === 0
  })));
});

// ---------- STRIPE (Checkout/Portal/Webhooks) --------------------------------
function requireStripeConfigs(res) {
  if (!stripe || !STRIPE_PRICE_PRO || !STRIPE_PRICE_AGENCY) {
    res.status(500).json({ error: "Stripe non configuré (env manquantes)." });
    return false;
  }
  return true;
}
app.post("/api/stripe/checkout", authMiddleware, async (req, res) => {
  try {
    if (!requireStripeConfigs(res)) return;
    const { plan } = req.body || {};
    const priceId = plan === "AGENCY" ? STRIPE_PRICE_AGENCY : STRIPE_PRICE_PRO;
    const u = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);

    const session = await stripe.checkout.sessions.create({
      mode: "subscription",
      customer: u.stripe_customer_id || undefined,
      line_items: [{ price: priceId, quantity: 1 }],
      success_url: `${SITE_URL}/account?status=success`,
      cancel_url: `${SITE_URL}/account?status=cancel`,
      metadata: { user_id: String(req.user.id), plan },
      allow_promotion_codes: true,
    });

    logAudit(req.user.id, "stripe_checkout_create", req, { plan });
    res.json({ url: session.url });
  } catch (e) { console.error(e); res.status(500).json({ error: "Erreur Stripe Checkout" }); }
});
app.post("/api/stripe/portal", authMiddleware, async (req, res) => {
  try {
    if (!stripe) return res.status(500).json({ error: "Stripe non configuré" });
    const u = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);
    if (!u?.stripe_customer_id) return res.status(400).json({ error: "Client Stripe introuvable" });
    const session = await stripe.billingPortal.sessions.create({
      customer: u.stripe_customer_id,
      return_url: `${SITE_URL}/account`,
    });
    logAudit(req.user.id, "stripe_portal_create", req);
    res.json({ url: session.url });
  } catch (e) { console.error(e); res.status(500).json({ error: "Erreur Stripe Portal" }); }
});
app.post("/api/stripe/webhook", express.raw({ type: "application/json" }), (req, res) => {
  if (!stripe || !STRIPE_WEBHOOK_SECRET) return res.status(500).send("Stripe non configuré");
  const sig = req.headers["stripe-signature"];
  let event;
  try { event = stripe.webhooks.constructEvent(req.body, sig, STRIPE_WEBHOOK_SECRET); }
  catch (err) { console.error("Webhook signature error:", err.message); return res.status(400).send(`Webhook Error: ${err.message}`); }

  const type = event.type;
  const obj = event.data.object;
  try {
    if (type === "customer.subscription.created" || type === "customer.subscription.updated") {
      const sub = obj;
      const customerId = sub.customer;
      const planLookup = sub.items?.data?.[0]?.price?.id === STRIPE_PRICE_AGENCY ? "AGENCY" : "PRO";
      const status = sub.status;
      const user = db.prepare("SELECT * FROM users WHERE stripe_customer_id = ?").get(customerId);
      if (user) {
        db.prepare("UPDATE users SET plan=?, subscription_status=?, quota_json=? WHERE id=?")
          .run(planLookup, status, JSON.stringify(quotasFor(planLookup)), user.id);
        const now = new Date().toISOString();
        const exists = db.prepare("SELECT id FROM subscriptions WHERE stripe_subscription_id = ?").get(sub.id);
        if (!exists) {
          db.prepare("INSERT INTO subscriptions (user_id, stripe_subscription_id, plan, status, current_period_end, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
            .run(user.id, sub.id, planLookup, status, sub.current_period_end, now, now);
        } else {
          db.prepare("UPDATE subscriptions SET plan=?, status=?, current_period_end=?, updated_at=? WHERE stripe_subscription_id=?")
            .run(planLookup, status, sub.current_period_end, now, sub.id);
        }
        logAudit(user.id, "stripe_subscription_sync", { headers: {} }, { type, plan: planLookup, status });
      }
    }
    if (type === "invoice.paid") {
      const customerId = obj.customer;
      const user = db.prepare("SELECT id FROM users WHERE stripe_customer_id = ?").get(customerId);
      if (user) logAudit(user.id, "stripe_invoice_paid", { headers: {} }, { hosted_invoice_url: obj.hosted_invoice_url });
    }
    if (type === "customer.subscription.deleted") {
      const sub = obj;
      const customerId = sub.customer;
      const user = db.prepare("SELECT * FROM users WHERE stripe_customer_id = ?").get(customerId);
      if (user) {
        db.prepare("UPDATE users SET plan='FREE', subscription_status='canceled', quota_json=? WHERE id=?")
          .run(JSON.stringify(quotasFor("FREE")), user.id);
        const now = new Date().toISOString();
        db.prepare("UPDATE subscriptions SET status='canceled', updated_at=? WHERE stripe_subscription_id=?")
          .run(now, sub.id);
        logAudit(user.id, "stripe_subscription_deleted", { headers: {} }, {});
      }
    }
  } catch (e) { console.error("Webhook handler error", e); }

  res.json({ received: true });
});

// ---------- PAIEMENTS BANCAIRES (CSV + matching) -----------------------------
/**
 * CSV attendu (séparateur ; ou ,) avec entêtes (case-insensitive) :
 * date, amount, reference, counterparty
 * amount en euros (ex: 750.00). Crédit = positif.
 */
app.post("/api/payments/bank/import", authMiddleware, requireRole(["OWNER","ADMIN","ACCOUNTANT"]), upload.single("file"), (req, res) => {
  if (!req.file) return res.status(400).json({ error: "Fichier requis" });
  const orgId = resolveOrgId(req);
  const raw = fs.readFileSync(req.file.path, "utf8");
  const lines = raw.split(/\r?\n/).filter(Boolean);
  if (lines.length < 2) return res.status(400).json({ error: "CSV vide" });

  const header = lines.shift().trim().toLowerCase();
  const sep = header.includes(";") ? ";" : ",";
  const cols = header.split(sep).map(s=>s.trim());
  const idx = {
    date: cols.findIndex(c => c.includes("date")),
    amount: cols.findIndex(c => c.includes("amount") || c.includes("montant")),
    reference: cols.findIndex(c => c.includes("reference") || c.includes("libell")),
    counterparty: cols.findIndex(c => c.includes("counterparty") || c.includes("emetteur") || c.includes("titulaire"))
  };
  if (idx.date<0 || idx.amount<0) return res.status(400).json({ error: "Colonnes manquantes (date/amount)" });

  const now = new Date().toISOString();
  let imported = 0;
  const stmt = db.prepare(`
    INSERT INTO bank_transactions (org_id, tx_date, amount_eur_cents, counterparty, reference, raw_json, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `);

  for (const line of lines) {
    const parts = line.split(sep).map(s=>s.trim());
    if (!parts[idx.amount]) continue;
    const d = parts[idx.date] || "";
    const ref = idx.reference>=0 ? parts[idx.reference] : "";
    const cp = idx.counterparty>=0 ? parts[idx.counterparty] : "";
    const amt = Number(String(parts[idx.amount]).replace(",", "."));
    if (!Number.isFinite(amt)) continue;
    const cents = Math.round(amt * 100);
    stmt.run(orgId, d, cents, cp || null, ref || null, JSON.stringify({ raw: parts }), now);
    imported++;
  }

  logAudit(req.user.id, "bank_import_csv", req, { imported });
  res.json({ ok: true, imported });
});

app.get("/api/payments/bank", authMiddleware, requireRole(["OWNER","ADMIN","ACCOUNTANT","VIEWER"]), (req, res) => {
  const orgId = resolveOrgId(req);
  const tx = db.prepare("SELECT * FROM bank_transactions WHERE org_id=? ORDER BY id DESC LIMIT 1000").all(orgId);
  const pendingInvoices = db.prepare("SELECT * FROM invoices WHERE org_id=? AND status!='Payé' ORDER BY id DESC").all(orgId);
  res.json({
    bank: tx,
    pending_invoices: pendingInvoices.map(r => ({ ...r, amount_usdc: r.amount_usdc_micro ? r.amount_usdc_micro/1_000_000 : null }))
  });
});

function markInvoicePaidEUR(invId, orgId, cents, note) {
  const inv = db.prepare("SELECT * FROM invoices WHERE id=? AND org_id=?").get(invId, orgId);
  if (!inv) return { ok:false, error:"Facture introuvable" };
  if (inv.currency !== "EUR") return { ok:false, error:"Devise facture non EUR" };
  if (inv.expected_eur_cents != null && Math.abs(inv.expected_eur_cents - cents) > 5) {
    return { ok:false, error:"Montant différent" };
  }
  db.prepare("UPDATE invoices SET status='Payé', paid_at=?, receipt_note=? WHERE id=? AND org_id=?")
    .run(new Date().toISOString(), note || null, invId, orgId);
  return { ok:true };
}
function markInvoicePaidUSDC(invId, orgId, micro, note) {
  const inv = db.prepare("SELECT * FROM invoices WHERE id=? AND org_id=?").get(invId, orgId);
  if (!inv) return { ok:false, error:"Facture introuvable" };
  if (inv.currency !== "USDC") return { ok:false, error:"Devise facture non USDC" };
  if (inv.amount_usdc_micro != null && Math.abs(inv.amount_usdc_micro - micro) > 100) {
    return { ok:false, error:"Montant différent" };
  }
  db.prepare("UPDATE invoices SET status='Payé', paid_at=?, receipt_note=? WHERE id=? AND org_id=?")
    .run(new Date().toISOString(), note || null, invId, orgId);
  return { ok:true };
}

app.post("/api/payments/reconcile", authMiddleware, requireRole(["OWNER","ADMIN","ACCOUNTANT"]), (req, res) => {
  const orgId = resolveOrgId(req);
  const { transaction_id, invoice_id } = req.body || {};
  if (!transaction_id || !invoice_id) return res.status(400).json({ error: "Champs requis" });
  const tx = db.prepare("SELECT * FROM bank_transactions WHERE id=? AND org_id=?").get(Number(transaction_id), orgId);
  if (!tx) return res.status(404).json({ error: "Transaction introuvable" });

  const inv = db.prepare("SELECT * FROM invoices WHERE id=? AND org_id=?").get(Number(invoice_id), orgId);
  if (!inv) return res.status(404).json({ error: "Facture introuvable" });

  if (inv.currency !== "EUR") return res.status(400).json({ error: "La facture n'est pas en EUR" });
  const r = markInvoicePaidEUR(inv.id, orgId, tx.amount_eur_cents, `Relevé bancaire ${tx.tx_date} ${tx.reference||""}`.trim());
  if (!r.ok) return res.status(400).json({ error: r.error });

  db.prepare("UPDATE bank_transactions SET matched_invoice_id=? WHERE id=? AND org_id=?").run(inv.id, tx.id, orgId);
  logAudit(req.user.id, "bank_reconcile", req, { tx_id: tx.id, invoice_id: inv.id });
  res.json({ ok: true });
});

app.post("/api/payments/auto-match", authMiddleware, requireRole(["OWNER","ADMIN","ACCOUNTANT"]), (req, res) => {
  const orgId = resolveOrgId(req);
  const pending = db.prepare("SELECT * FROM invoices WHERE org_id=? AND status!='Payé'").all(orgId);
  const tenants = db.prepare("SELECT id, name FROM tenants WHERE org_id=?").all(orgId);
  const tmap = new Map(tenants.map(t => [t.id, t.name.toLowerCase()]));

  let matched = 0;
  const txs = db.prepare("SELECT * FROM bank_transactions WHERE org_id=? AND matched_invoice_id IS NULL").all(orgId);

  for (const tx of txs) {
    const ref = (tx.reference || "").toLowerCase();
    let invId = null;

    // Règle 1: référence contient "#INV-<id>"
    const m = ref.match(/#?inv[- ]?(\d+)/i) || ref.match(/\b(\d{1,6})\b/);
    if (m) {
      const candidate = Number(m[1]);
      const inv = pending.find(p => p.id === candidate && p.currency === "EUR");
      if (inv && Math.abs(inv.expected_eur_cents - tx.amount_eur_cents) <= 5) invId = inv.id;
    }

    // Règle 2: nom locataire + montant exact
    if (!invId) {
      for (const inv of pending) {
        if (inv.currency !== "EUR") continue;
        const tenantName = (tmap.get(inv.tenant_id) || "");
        if (tenantName && ref.includes(tenantName.toLowerCase()) && Math.abs(inv.expected_eur_cents - tx.amount_eur_cents) <= 5) {
          invId = inv.id; break;
        }
      }
    }

    if (invId) {
      const r = markInvoicePaidEUR(invId, orgId, tx.amount_eur_cents, `Auto-match bancaire ${tx.tx_date}`);
      if (r.ok) {
        db.prepare("UPDATE bank_transactions SET matched_invoice_id=? WHERE id=? AND org_id=?").run(invId, tx.id, orgId);
        matched++;
      }
    }
  }

  logAudit(req.user.id, "bank_auto_match", req, { matched });
  res.json({ ok: true, matched });
});

// ---------- PAIEMENTS CRYPTO (USDC) ------------------------------------------
app.get("/api/payments/crypto", authMiddleware, requireRole(["OWNER","ADMIN","ACCOUNTANT","VIEWER"]), (req, res) => {
  const orgId = resolveOrgId(req);
  const rows = db.prepare("SELECT * FROM crypto_payments WHERE org_id=? ORDER BY id DESC LIMIT 1000").all(orgId);
  const pending = db.prepare("SELECT * FROM invoices WHERE org_id=? AND status!='Payé' AND currency='USDC'").all(orgId);
  res.json({ crypto: rows.map(r => ({ ...r, amount_usdc: r.amount_usdc_micro/1_000_000 })), pending_usdc: pending.map(p=>({ ...p, amount_usdc: p.amount_usdc_micro/1_000_000 })) });
});

/** Simulation / Webhook générique d'un paiement USDC reçu.
 * body: { network, tx_hash, amount_usdc, reference }
 */
app.post("/api/crypto/ingest", authMiddleware, requireRole(["OWNER","ADMIN","ACCOUNTANT"]), (req, res) => {
  const orgId = resolveOrgId(req);
  const { network="polygon", tx_hash, amount_usdc, reference="" } = req.body || {};
  if (!tx_hash || !Number.isFinite(amount_usdc)) return res.status(400).json({ error: "Paramètres invalides" });

  const now = new Date().toISOString();
  const info = db.prepare(`
    INSERT INTO crypto_payments (org_id, network, tx_hash, currency, amount_usdc_micro, reference, status, created_at)
    VALUES (?, ?, ?, 'USDC', ?, ?, 'received', ?)
  `).run(orgId, network, tx_hash, Math.round(amount_usdc*1_000_000), reference, now);

  logAudit(req.user.id, "crypto_ingest", req, { id: info.lastInsertRowid, tx: tx_hash });
  res.json({ ok: true, id: info.lastInsertRowid });
});

/** Apparier manuellement ou auto via référence (#INV-123)
 * body: { payment_id, invoice_id? }
 */
app.post("/api/crypto/reconcile", authMiddleware, requireRole(["OWNER","ADMIN","ACCOUNTANT"]), (req, res) => {
  const orgId = resolveOrgId(req);
  const { payment_id, invoice_id } = req.body || {};
  if (!payment_id) return res.status(400).json({ error: "payment_id requis" });
  const pay = db.prepare("SELECT * FROM crypto_payments WHERE id=? AND org_id=?").get(Number(payment_id), orgId);
  if (!pay) return res.status(404).json({ error: "Paiement introuvable" });

  let inv = null;
  if (invoice_id) {
    inv = db.prepare("SELECT * FROM invoices WHERE id=? AND org_id=?").get(Number(invoice_id), orgId);
  } else {
    const ref = (pay.reference || "").toLowerCase();
    const m = ref.match(/#?inv[- ]?(\d+)/i);
    if (m) {
      const invId = Number(m[1]);
      inv = db.prepare("SELECT * FROM invoices WHERE id=? AND org_id=?").get(invId, orgId);
    }
  }
  if (!inv) return res.status(400).json({ error: "Impossible d’identifier la facture" });
  if (inv.currency !== "USDC") return res.status(400).json({ error: "Facture non USDC" });

  const r = markInvoicePaidUSDC(inv.id, orgId, pay.amount_usdc_micro, `Paiement crypto ${pay.network} ${pay.tx_hash}`);
  if (!r.ok) return res.status(400).json({ error: r.error });

  db.prepare("UPDATE crypto_payments SET matched_invoice_id=?, status='matched' WHERE id=? AND org_id=?")
    .run(inv.id, pay.id, orgId);

  logAudit(req.user.id, "crypto_reconcile", req, { payment_id: pay.id, invoice_id: inv.id });
  res.json({ ok: true });
});

// ----------------------- ROUTES SENSIBLES (AJOUT) ----------------------------
require(path.join(__dirname, "server", "sensitive-actions"))({
  app,
  db,
  secret: SECRET,
  authMiddleware,
  logAudit
});

// ---------- START -------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`RentChain API running on http://localhost:${PORT}`);
});
