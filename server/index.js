// index.js — RentChain API (CJS) — intégration DIRECTE des routes "actions sensibles" pour éviter tout souci de require
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const compression = require("compression");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const Database = require("better-sqlite3");
const PDFDocument = require("pdfkit");
const crypto = require("crypto");
const { parse: parseCSV } = require("csv-parse/sync");
const { v4: uuidv4 } = require("uuid");

// ----------------- Config -----------------
const PORT = Number(process.env.PORT || 4000);
const CLIENT_ORIGINS = String(process.env.CLIENT_ORIGINS || "http://localhost:5173,http://127.0.0.1:5173")
  .split(",").map(s=>s.trim()).filter(Boolean);
const DB_PATH = process.env.DB_PATH || path.join(__dirname, "rentchain.db");
const FILES_DIR = process.env.FILES_DIR || path.join(__dirname, "uploads");
const MEDIA_DIR = process.env.MEDIA_DIR || path.join(__dirname, "public_uploads");
const JWT_SECRET = process.env.JWT_SECRET || "change_me";
const ENC_KEY_B64 = process.env.FILE_ENCRYPTION_KEY || "";
const IS_PROD = process.env.NODE_ENV === "production";

const OPENBANKING_PROVIDER = (process.env.OPENBANKING_PROVIDER || "mock").toLowerCase();

if (!fs.existsSync(FILES_DIR)) fs.mkdirSync(FILES_DIR, { recursive: true });
if (!fs.existsSync(MEDIA_DIR)) fs.mkdirSync(MEDIA_DIR, { recursive: true });

const db = new Database(DB_PATH);

// ----------------- Schéma DB (existant + ce qu’il faut) -----------------
db.prepare(`
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE, name TEXT, company TEXT,
  password_hash TEXT, created_at TEXT,
  stripe_customer_id TEXT, subscription_status TEXT, plan TEXT,
  quota_json TEXT
)`).run();

db.prepare(`CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT)`).run();
try { db.prepare("INSERT INTO settings(key,value) VALUES('sensitive_password_hash','')").run(); } catch {}

db.prepare(`
CREATE TABLE IF NOT EXISTS organizations(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL, created_at TEXT NOT NULL
)`).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS org_members(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER NOT NULL, user_id INTEGER NOT NULL, role TEXT NOT NULL,
  UNIQUE(org_id,user_id)
)`).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS api_tokens(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER NOT NULL, name TEXT NOT NULL, token_hash TEXT NOT NULL,
  created_at TEXT NOT NULL, last_used_at TEXT
)`).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS properties(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER, user_id INTEGER, name TEXT NOT NULL, deleted_at TEXT
)`).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS tenants(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER, user_id INTEGER, property_id INTEGER NOT NULL,
  name TEXT NOT NULL, unit TEXT, address TEXT,
  lease_path TEXT, lease_uploaded_at TEXT, deleted_at TEXT
)`).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS tenant_files(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER, user_id INTEGER, tenant_id INTEGER NOT NULL,
  label TEXT, file_path TEXT, uploaded_at TEXT
)`).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS invoices(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER, user_id INTEGER, tenant_id INTEGER NOT NULL,
  currency TEXT NOT NULL, expected_eur_cents INTEGER, amount_usdc_micro INTEGER,
  status TEXT NOT NULL, due_date TEXT, paid_at TEXT, receipt_note TEXT,
  reference TEXT, paid_usdc_micro INTEGER DEFAULT 0, paid_eur_cents INTEGER DEFAULT 0,
  paid_via_cash INTEGER DEFAULT 0
)`).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS payment_meta(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  invoice_id INTEGER UNIQUE NOT NULL,
  provider TEXT, external_id TEXT, pm_id TEXT, customer_id TEXT,
  last_event TEXT, failure_code TEXT, updated_at TEXT
)`).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS audit_logs(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER, action TEXT NOT NULL, ip TEXT, ua TEXT, meta TEXT, created_at TEXT NOT NULL
)`).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS bank_transactions(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER NOT NULL, tx_date TEXT NOT NULL,
  amount_eur_cents INTEGER NOT NULL, counterparty TEXT, reference TEXT,
  raw_json TEXT, matched_invoice_id INTEGER, created_at TEXT NOT NULL
)`).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS crypto_payments(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER NOT NULL, network TEXT, tx_hash TEXT, currency TEXT,
  amount_usdc_micro INTEGER, reference TEXT, matched_invoice_id INTEGER,
  status TEXT NOT NULL, created_at TEXT NOT NULL
)`).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS site_media(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  filename TEXT NOT NULL, label TEXT, mime TEXT, size_bytes INTEGER, uploaded_at TEXT NOT NULL
)`).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS refresh_tokens(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  token_hash TEXT NOT NULL,
  ua TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT
)`).run();
db.prepare(`CREATE UNIQUE INDEX IF NOT EXISTS idx_rt_hash ON refresh_tokens(token_hash)`).run();

db.prepare(`
CREATE TABLE IF NOT EXISTS bank_links(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  org_id INTEGER NOT NULL,
  provider TEXT NOT NULL,
  access_token_enc TEXT,
  cursor TEXT,
  status TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT
)`).run();

try { db.prepare("ALTER TABLE invoices ADD COLUMN reference TEXT").run(); } catch {}
try { db.prepare("ALTER TABLE bank_transactions ADD COLUMN reference TEXT").run(); } catch {}

db.prepare(`CREATE INDEX IF NOT EXISTS idx_props_org ON properties(org_id)`).run();
db.prepare(`CREATE INDEX IF NOT EXISTS idx_tenants_org ON tenants(org_id)`).run();
db.prepare(`CREATE INDEX IF NOT EXISTS idx_invoices_org ON invoices(org_id)`).run();
db.prepare(`CREATE INDEX IF NOT EXISTS idx_bank_org ON bank_transactions(org_id)`).run();

// ----------------- Helpers -----------------
const DEFAULT_QUOTAS = {
  FREE:   { properties: 1,   tenants: 5,    storageMB: 20   },
  PRO:    { properties: 10,  tenants: 200,  storageMB: 1000 },
  AGENCY: { properties: 100, tenants: 5000, storageMB: 10000}
};
const ROLES = ["OWNER","ADMIN","AGENT","ACCOUNTANT","VIEWER"];

function quotasFor(plan){ return DEFAULT_QUOTAS[(plan || "FREE").toUpperCase()] || DEFAULT_QUOTAS.FREE; }
function ensureUserQuotasRow(u){
  if (!u.quota_json) {
    const q = JSON.stringify(quotasFor(u.plan || "FREE"));
    db.prepare("UPDATE users SET quota_json=? WHERE id=?").run(q, u.id);
    u.quota_json = q;
  }
  try { return JSON.parse(u.quota_json); } catch { return quotasFor(u.plan || "FREE"); }
}

function getDeletePasswordHash(){
  const row = db.prepare("SELECT value FROM settings WHERE key='delete_password_hash'").get();
  return row?.value || null;
}
function setDeletePasswordHash(hash){
  db.prepare(`
    INSERT INTO settings(key,value) VALUES('delete_password_hash',?)
    ON CONFLICT(key) DO UPDATE SET value=excluded.value
  `).run(hash);
}

function signAccessToken(payload){
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "15m" });
}
function cookieOpts(){ return { httpOnly:true, sameSite:"lax", secure:IS_PROD, path:"/" }; }

function authMiddleware(req,res,next){
  try{
    const token = req.cookies?.token || (req.headers.authorization && req.headers.authorization.split(" ")[1]);
    if (!token) return res.status(401).json({ error:"Non autorisé" });
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  }catch{
    return res.status(401).json({ error:"Token invalide" });
  }
}

function ensureOrgOnSignup(userId, orgName){
  const has = db.prepare("SELECT org_id FROM org_members WHERE user_id=?").get(userId);
  if (has?.org_id) return has.org_id;
  const now = new Date().toISOString();
  const info = db.prepare("INSERT INTO organizations(name,created_at) VALUES(?,?)").run(orgName || "Mon agence", now);
  db.prepare("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,?)").run(info.lastInsertRowid, userId, "OWNER");
  return info.lastInsertRowid;
}

function currentMembership(req){
  const userId = req.user?.id;
  if (!userId) return null;
  const wantedOrg = req.headers["x-org"] ? Number(req.headers["x-org"]) : null;
  if (wantedOrg) {
    const m = db.prepare("SELECT org_id, user_id, role FROM org_members WHERE user_id=? AND org_id=?")
      .get(userId, wantedOrg);
    if (m) return m;
  }
  let m = db.prepare("SELECT org_id, user_id, role FROM org_members WHERE user_id=? ORDER BY id ASC").get(userId);
  if (m) return m;
  const u = db.prepare("SELECT email,name,company FROM users WHERE id=?").get(userId);
  const orgName = (u?.company || u?.name || u?.email || "Mon agence") + "";
  const now = new Date().toISOString();
  const ins = db.prepare("INSERT INTO organizations(name, created_at) VALUES(?,?)").run(orgName, now);
  db.prepare("INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,?)").run(ins.lastInsertRowid, userId, "OWNER");
  return { org_id: ins.lastInsertRowid, user_id: userId, role: "OWNER" };
}

function logAudit(userId, action, req, metaObj){
  const ip = req.headers["x-forwarded-for"]?.split(",")[0]?.trim() || req.socket?.remoteAddress || "";
  const ua = req.headers["user-agent"] || "";
  const meta = metaObj ? JSON.stringify(metaObj) : null;
  db.prepare("INSERT INTO audit_logs(user_id,action,ip,ua,meta,created_at) VALUES(?,?,?,?,?,?)")
    .run(userId || null, action, ip, ua, meta, new Date().toISOString());
}

function encOn(){ return !!ENC_KEY_B64; }
function encKey(){ return Buffer.from(ENC_KEY_B64, "base64"); }
function encryptBuffer(buf){
  if (!encOn()) return buf;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", encKey(), iv);
  const enc = Buffer.concat([cipher.update(buf), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([Buffer.from("RCv1"), iv, tag, enc]);
}
function encryptString(s){
  if (!encOn()) return s;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", encKey(), iv);
  const enc = Buffer.concat([cipher.update(String(s), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([Buffer.from("RSv1"), iv, tag, enc]).toString("base64");
}

// refresh tokens
function randomToken(){ return crypto.randomBytes(48).toString("base64url"); }
function hashToken(t){ return crypto.createHash("sha256").update(t).digest("hex"); }
function storeRefresh(userId, token, ua, days = 14){
  const now = new Date();
  const expires = new Date(now.getTime() + days*24*3600*1000);
  db.prepare(`
    INSERT INTO refresh_tokens(user_id, token_hash, ua, created_at, expires_at)
    VALUES(?,?,?,?,?)
  `).run(userId, hashToken(token), ua || "", now.toISOString(), expires.toISOString());
  return { token, expires };
}
function findRefresh(t){
  if (!t) return null;
  const row = db.prepare("SELECT * FROM refresh_tokens WHERE token_hash=?").get(hashToken(t));
  if (!row) return null;
  if (row.revoked_at) return null;
  if (new Date(row.expires_at) < new Date()) return null;
  return row;
}
function revokeRefresh(t){
  try{
    db.prepare("UPDATE refresh_tokens SET revoked_at=? WHERE token_hash=? AND revoked_at IS NULL")
      .run(new Date().toISOString(), hashToken(t));
  }catch{}
}

// ----------------- App -----------------
const app = express();

app.set("trust proxy", 1);
app.use(cookieParser());
app.use(cors({
  origin(origin, cb){
    if (!origin || CLIENT_ORIGINS.includes(origin)) return cb(null, true);
    return cb(null, false);
  },
  credentials: true,
  methods: ["GET","POST","DELETE","PUT","PATCH","OPTIONS"],
  allowedHeaders: ["Content-Type","Authorization","X-Org","X-API-Key"]
}));
app.use((req,res,next)=>{ res.setHeader("Vary","Origin"); next(); });

app.disable("x-powered-by");
app.use(helmet());
app.use(compression());
app.use(rateLimit({ windowMs: 60_000, limit: 800 }));

app.use((req,res,next)=>{
  if (req.originalUrl === "/api/stripe/webhook" || req.originalUrl === "/api/crypto/webhook") return next();
  express.json({ limit:"4mb" })(req,res,next);
});

app.use("/api/files", express.static(FILES_DIR));
app.use("/api/media", express.static(MEDIA_DIR));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024 },
  fileFilter(req, file, cb){
    const ok = /^(image\/(png|jpe?g|webp|gif)|application\/pdf|text\/csv)$/.test(file.mimetype || "");
    cb(ok ? null : new Error("TYPE"), ok);
  }
});

// Health
app.get("/api/health", (req,res)=>res.json({ ok:true }));

// ----------------- SSE -----------------
const sseClients = new Set();
app.get("/api/events", (req,res)=>{
  res.set({
    "Content-Type":"text/event-stream",
    "Cache-Control":"no-cache",
    "Connection":"keep-alive"
  });
  res.flushHeaders();
  const client = { res };
  sseClients.add(client);
  const ping = setInterval(()=>{ try{ res.write("event: ping\ndata: {}\n\n"); }catch{} }, 30000);
  res.write("event: hello\ndata: {}\n\n");
  req.on("close", ()=>{ clearInterval(ping); sseClients.delete(client); });
});
function broadcast(event, payload = {}) {
  const msg = `event: ${event}\ndata: ${JSON.stringify(payload)}\n\n`;
  for (const { res } of sseClients) { try{ res.write(msg); }catch{} }
}

// ----------------- AUTH -----------------
app.post("/api/signup", (req,res)=>{
  const { email, password, name, company, remember=true } = req.body || {};
  if (!email || !password) return res.status(400).json({ error:"Email + mot de passe requis" });
  const has = db.prepare("SELECT id FROM users WHERE email=?").get(email);
  if (has) return res.status(400).json({ error:"Email déjà utilisé" });
  const now = new Date().toISOString();
  const hash = bcrypt.hashSync(password, 10);
  const info = db.prepare(`
    INSERT INTO users(email,name,company,password_hash,created_at,subscription_status,plan)
    VALUES(?,?,?,?,?,'inactive','FREE')
  `).run(email, name||"", company||"", hash, now);
  const userId = info.lastInsertRowid;

  const access = signAccessToken({ id:userId, email });
  const rt = randomToken();
  const days = remember ? 90 : 14;
  storeRefresh(userId, rt, req.headers["user-agent"], days);

  res.cookie("token", access, { ...cookieOpts(), maxAge: 15*60*1000 });
  res.cookie("rt", rt, { ...cookieOpts(), maxAge: days*24*3600*1000 });

  ensureOrgOnSignup(userId, company || "Mon agence");
  res.json({ ok:true });
});

app.post("/api/login", (req,res)=>{
  const { email, password, remember=true } = req.body || {};
  const u = db.prepare("SELECT * FROM users WHERE email=?").get(email || "");
  if (!u || !bcrypt.compareSync(password || "", u.password_hash || "")) {
    return res.status(401).json({ error:"Identifiants invalides" });
  }

  const access = signAccessToken({ id:u.id, email:u.email });
  const rt = randomToken();
  const days = remember ? 90 : 14;
  storeRefresh(u.id, rt, req.headers["user-agent"], days);

  res.cookie("token", access, { ...cookieOpts(), maxAge: 15*60*1000 });
  res.cookie("rt", rt, { ...cookieOpts(), maxAge: days*24*3600*1000 });

  ensureOrgOnSignup(u.id, u.company || "Mon agence");
  res.json({ ok:true });
});

app.post("/api/auth/refresh", (req,res)=>{
  const rt = req.cookies?.rt;
  const row = findRefresh(rt);
  if (!row) return res.status(401).json({ error:"Refresh invalide" });

  // rotation
  revokeRefresh(rt);
  const user = db.prepare("SELECT id,email FROM users WHERE id=?").get(row.user_id);
  if (!user) return res.status(401).json({ error:"User introuvable" });

  const access = signAccessToken({ id:user.id, email:user.email });
  const newRt = randomToken();
  storeRefresh(user.id, newRt, req.headers["user-agent"], 14);

  res.cookie("token", access, { ...cookieOpts(), maxAge: 15*60*1000 });
  res.cookie("rt", newRt, { ...cookieOpts(), maxAge: 14*24*3600*1000 });
  res.json({ ok:true });
});

app.post("/api/logout", (req,res)=>{
  const rt = req.cookies?.rt;
  if (rt) revokeRefresh(rt);
  res.clearCookie("token", { ...cookieOpts(), maxAge: 0 });
  res.clearCookie("rt", { ...cookieOpts(), maxAge: 0 });
  return res.json({ ok:true });
});

app.get("/api/me", authMiddleware, (req,res)=>{
  const u = db.prepare("SELECT * FROM users WHERE id=?").get(req.user.id);
  if (!u) return res.status(401).json({ error:"Not found" });
  const quotas = ensureUserQuotasRow(u);
  const mem = currentMembership(req);
  res.json({
    id: u.id, email: u.email, name: u.name, company: u.company,
    plan: u.plan || "FREE", subscription_status: u.subscription_status || "inactive",
    quotas, org_id: mem?.org_id || null, encryption: ENC_KEY_B64 ? "on" : "off"
  });
});

// ----------------- ROUTES "ACTIONS SENSIBLES" — intégrées ici -----------------
const STEP_UP_TTL = Number(process.env.STEP_UP_TTL || 300);
const getSensitiveHash = () => (db.prepare("SELECT value FROM settings WHERE key='sensitive_password_hash'").get()?.value || "");
const setSensitiveHash = (h) => db.prepare(`
  INSERT INTO settings(key,value) VALUES('sensitive_password_hash',?)
  ON CONFLICT(key) DO UPDATE SET value=excluded.value
`).run(h);

// ping public (debug)
app.get("/api/security/_ping", (_req,res)=>res.json({ ok:true }));

// statut
app.get("/api/security/sensitive-password/status", authMiddleware, (_req,res)=>{
  res.json({ defined: !!getSensitiveHash() });
});

// définir / modifier
app.post("/api/security/sensitive-password", authMiddleware, (req,res)=>{
  const { password, old_password } = req.body || {};
  const newPwd = String(password || "").trim();
  if (!newPwd || newPwd.length < 6) return res.status(400).json({ error:"≥ 6 caractères" });

  const existing = getSensitiveHash();
  if (existing) {
    const ok = bcrypt.compareSync(String(old_password || ""), existing);
    if (!ok) return res.status(401).json({ error:"Ancien mot de passe incorrect" });
  }
  setSensitiveHash(bcrypt.hashSync(newPwd, 10));
  try { logAudit?.(req.user.id, existing ? "sensitive_update" : "sensitive_set", req); } catch {}
  res.json({ ok:true });
});

// reset via mdp de compte
app.post("/api/security/sensitive-password/reset", authMiddleware, (req,res)=>{
  const { account_password, password } = req.body || {};
  const accPwd = String(account_password || "");
  const newPwd = String(password || "").trim();
  if (!newPwd || newPwd.length < 6) return res.status(400).json({ error:"≥ 6 caractères" });
  const u = db.prepare("SELECT password_hash FROM users WHERE id=?").get(req.user.id);
  if (!u?.password_hash || !bcrypt.compareSync(accPwd, u.password_hash)) {
    return res.status(401).json({ error:"Mot de passe de compte invalide" });
  }
  setSensitiveHash(bcrypt.hashSync(newPwd, 10));
  try { logAudit?.(req.user.id, "sensitive_reset", req); } catch {}
  res.json({ ok:true });
});

// step-up
function signStepUp(userId){
  const exp = Math.floor(Date.now()/1000) + STEP_UP_TTL;
  const stepUpToken = jwt.sign({ typ:"stepup_sensitive", sub:String(userId), exp }, JWT_SECRET);
  return { stepUpToken, exp };
}
function verifyStepUp(req,res,next){
  const tok = String(req.headers.authorization||"").replace(/^Bearer\s+/i,"");
  if (!tok) return res.status(401).json({ error:"step-up requis" });
  try{
    const p = jwt.verify(tok, JWT_SECRET);
    if (p.typ!=="stepup_sensitive") throw new Error("type");
    if (String(p.sub)!==String(req.user.id)) throw new Error("sub");
    next();
  }catch{ return res.status(401).json({ error:"step-up invalide/expiré" }); }
}
app.post("/api/auth/step-up-sensitive", authMiddleware, (req,res)=>{
  const hash = getSensitiveHash();
  if (!hash) return res.status(409).json({ error:"non défini" });
  const ok = bcrypt.compareSync(String(req.body?.password || ""), hash);
  if (!ok) return res.status(401).json({ error:"Mot de passe sensible invalide" });
  const { stepUpToken, exp } = signStepUp(req.user.id);
  try { logAudit?.(req.user.id, "stepup_sensitive_ok", req); } catch {}
  res.json({ stepUpToken, exp });
});

// helpers facture (pour cash)
function updateInvoiceStatus(invId){
  const inv = db.prepare("SELECT * FROM invoices WHERE id=?").get(invId);
  if (!inv) return;
  const nowISO = new Date().toISOString();
  if (inv.currency === "EUR") {
    const due = Number(inv.expected_eur_cents || 0);
    const paid = Number(inv.paid_eur_cents || 0);
    if (due>0 && paid>=due) db.prepare("UPDATE invoices SET status='Payé', paid_at=? WHERE id=?").run(nowISO, inv.id);
    else if (paid>0 && paid<due) db.prepare("UPDATE invoices SET status='Partiel', paid_at=NULL WHERE id=?").run(inv.id);
    else db.prepare("UPDATE invoices SET status='En attente', paid_at=NULL WHERE id=?").run(inv.id);
  } else {
    const due = Number(inv.amount_usdc_micro || 0);
    const paid = Number(inv.paid_usdc_micro || 0);
    if (due>0 && paid>=due) db.prepare("UPDATE invoices SET status='Payé', paid_at=? WHERE id=?").run(nowISO, inv.id);
    else if (paid>0 && paid<due) db.prepare("UPDATE invoices SET status='Partiel', paid_at=NULL WHERE id=?").run(inv.id);
    else db.prepare("UPDATE invoices SET status='En attente', paid_at=NULL WHERE id=?").run(inv.id);
  }
}

// cash mark / unmark
app.post("/api/payments/cash/mark", authMiddleware, verifyStepUp, (req,res)=>{
  const { invoice_id } = req.body || {};
  const inv = db.prepare("SELECT * FROM invoices WHERE id=?").get(Number(invoice_id));
  if (!inv) return res.status(404).json({ error:"Facture introuvable" });
  if (inv.currency === "EUR"){
    const due = Number(inv.expected_eur_cents || 0);
    db.prepare("UPDATE invoices SET paid_eur_cents=?, paid_via_cash=1 WHERE id=?").run(due, inv.id);
  } else {
    const due = Number(inv.amount_usdc_micro || 0);
    db.prepare("UPDATE invoices SET paid_usdc_micro=?, paid_via_cash=1 WHERE id=?").run(due, inv.id);
  }
  updateInvoiceStatus(inv.id);
  try { logAudit?.(req.user.id, "invoice_mark_cash", req, { invoice_id: inv.id }); } catch {}
  res.json({ ok:true });
});
app.post("/api/payments/cash/unmark", authMiddleware, verifyStepUp, (req,res)=>{
  const { invoice_id } = req.body || {};
  const inv = db.prepare("SELECT * FROM invoices WHERE id=?").get(Number(invoice_id));
  if (!inv) return res.status(404).json({ error:"Facture introuvable" });
  if (inv.currency === "EUR"){
    db.prepare("UPDATE invoices SET paid_eur_cents=0, paid_via_cash=0 WHERE id=?").run(inv.id);
  } else {
    db.prepare("UPDATE invoices SET paid_usdc_micro=0, paid_via_cash=0 WHERE id=?").run(inv.id);
  }
  updateInvoiceStatus(inv.id);
  try { logAudit?.(req.user.id, "invoice_unmark_cash", req, { invoice_id: inv.id }); } catch {}
  res.json({ ok:true });
});

// ----------------- Settings -----------------
app.post("/api/settings/delete-password", authMiddleware, (req,res)=>{
  const { password } = req.body || {};
  if (!password || password.length < 6) return res.status(400).json({ error:"≥ 6 caractères" });
  const hash = bcrypt.hashSync(password, 10);
  setDeletePasswordHash(hash);
  res.json({ ok:true });
});

// ----------------- Orgs / Members / Keys -----------------
app.get("/api/orgs", authMiddleware, (req,res)=>{
  const rows = db.prepare(`
    SELECT o.* FROM organizations o
    JOIN org_members m ON m.org_id=o.id
    WHERE m.user_id=? ORDER BY o.id ASC
  `).all(req.user.id);
  res.json(rows);
});
app.get("/api/members", authMiddleware, (req,res)=>{
  const mem = currentMembership(req);
  const rows = db.prepare(`
    SELECT m.user_id, m.role, u.email, u.name
    FROM org_members m LEFT JOIN users u ON u.id=m.user_id
    WHERE m.org_id=? ORDER BY m.id ASC
  `).all(mem.org_id);
  res.json(rows);
});
app.post("/api/members", authMiddleware, (req,res)=>{
  const mem = currentMembership(req);
  const { email, role } = req.body || {};
  if (!email || !ROLES.includes(role)) return res.status(400).json({ error:"Params invalides" });
  const u = db.prepare("SELECT * FROM users WHERE email=?").get(email);
  if (!u) return res.status(400).json({ error:"Utilisateur introuvable" });
  db.prepare(`
    INSERT INTO org_members(org_id,user_id,role) VALUES(?,?,?)
    ON CONFLICT(org_id,user_id) DO UPDATE SET role=excluded.role
  `).run(mem.org_id, u.id, role);
  res.json({ ok:true });
});
app.delete("/api/members/:userId", authMiddleware, (req,res)=>{
  const mem = currentMembership(req);
  const userId = Number(req.params.userId);
  db.prepare("DELETE FROM org_members WHERE org_id=? AND user_id=?").run(mem.org_id, userId);
  res.json({ ok:true });
});

// ----------------- Properties -----------------
app.get("/api/properties", authMiddleware, (req,res)=>{
  const mem = currentMembership(req);
  const showArchived = String(req.query.include_archived || "") === "1";
  const rows = db.prepare(`
    SELECT * FROM properties WHERE org_id=? ${showArchived ? "" : "AND deleted_at IS NULL"} ORDER BY id ASC
  `).all(mem.org_id);
  res.json(rows);
});
app.post("/api/properties", authMiddleware, (req,res)=>{
  const mem = currentMembership(req);
  const { name } = req.body || {};
  if (!name?.trim()) return res.status(400).json({ error:"Nom requis" });

  const u = db.prepare("SELECT * FROM users WHERE id=?").get(req.user.id);
  const quotas = ensureUserQuotasRow(u);
  const count = db.prepare("SELECT COUNT(*) c FROM properties WHERE org_id=? AND deleted_at IS NULL").get(mem.org_id).c;
  if (count >= quotas.properties) return res.status(403).json({ error:"Quota immeubles atteint" });

  const info = db.prepare("INSERT INTO properties(org_id,user_id,name) VALUES(?,?,?)")
    .run(mem.org_id, req.user.id, name.trim());
  res.json({ id: info.lastInsertRowid, name });
});
app.delete("/api/properties/:id", authMiddleware, (req,res)=>{
  const mem = currentMembership(req);
  const id = Number(req.params.id);
  const { password } = req.body || {};
  const hash = getDeletePasswordHash();
  if (!hash || !bcrypt.compareSync(password || "", hash)) {
    return res.status(401).json({ error:"Mot de passe invalide" });
  }
  const now = new Date().toISOString();
  db.prepare("UPDATE properties SET deleted_at=? WHERE org_id=? AND id=?").run(now, mem.org_id, id);
  res.json({ ok:true });
});
app.post("/api/properties/:id/restore", authMiddleware, (req,res)=>{
  const mem = currentMembership(req);
  const id = Number(req.params.id);
  db.prepare("UPDATE properties SET deleted_at=NULL WHERE org_id=? AND id=?").run(mem.org_id, id);
  res.json({ ok:true });
});

// ----------------- Tenants + fichiers -----------------
app.get("/api/tenants", authMiddleware, (req,res)=>{
  const mem = currentMembership(req);
  const showArchived = String(req.query.include_archived || "") === "1";
  const propertyId = req.query.property_id ? Number(req.query.property_id) : null;
  const rows = db.prepare(`
    SELECT * FROM tenants
    WHERE org_id=? ${showArchived ? "" : "AND deleted_at IS NULL"}
    ${propertyId ? "AND property_id=?" : ""} ORDER BY id ASC
  `).all(propertyId ? [mem.org_id, propertyId] : [mem.org_id]);
  const enrich = rows.map(t=>{
    const files = db.prepare("SELECT id,label,file_path FROM tenant_files WHERE tenant_id=? ORDER BY id ASC").all(t.id)
      .map(f=>({ id:f.id, label:f.label, filename:path.basename(f.file_path), url:`/api/files/${path.basename(f.file_path)}` }));
    return { ...t, files };
  });
  res.json(enrich);
});
app.post("/api/tenants", authMiddleware, (req,res)=>{
  const mem = currentMembership(req);
  const { property_id, name, unit } = req.body || {};
  if (!property_id || !name?.trim()) return res.status(400).json({ error:"Paramètres invalides" });

  const u = db.prepare("SELECT * FROM users WHERE id=?").get(req.user.id);
  const quotas = ensureUserQuotasRow(u);
  const activeCount = db.prepare("SELECT COUNT(*) c FROM tenants WHERE org_id=? AND deleted_at IS NULL")
    .get(mem.org_id).c;
  if (activeCount >= quotas.tenants) return res.status(403).json({ error:"Quota locataires atteint" });

  const info = db.prepare(`
    INSERT INTO tenants(org_id,user_id,property_id,name,unit) VALUES(?,?,?,?,?)
  `).run(mem.org_id, req.user.id, property_id, name.trim(), (unit||"").trim());
  res.json({ id: info.lastInsertRowid });
});
app.post("/api/tenants/:id", authMiddleware, (req,res)=>{
  const mem = currentMembership(req);
  const id = Number(req.params.id);
  const { name, unit, address } = req.body || {};
  db.prepare("UPDATE tenants SET name=?,unit=?,address=? WHERE org_id=? AND id=?")
    .run(name||"", unit||"", address||"", mem.org_id, id);
  res.json({ ok:true });
});
app.delete("/api/tenants/:id", authMiddleware, (req,res)=>{
  const mem = currentMembership(req);
  const id = Number(req.params.id);
  const { password } = req.body || {};
  const hash = getDeletePasswordHash();
  if (!hash || !bcrypt.compareSync(password || "", hash)) {
    return res.status(401).json({ error:"Mot de passe invalide" });
  }
  const now = new Date().toISOString();
  db.prepare("UPDATE tenants SET deleted_at=? WHERE org_id=? AND id=?").run(now, mem.org_id, id);
  res.json({ ok:true });
});
app.post("/api/tenants/:id/restore", authMiddleware, (req,res)=>{
  const mem = currentMembership(req);
  const id = Number(req.params.id);
  db.prepare("UPDATE tenants SET deleted_at=NULL WHERE org_id=? AND id=?").run(mem.org_id, id);
  res.json({ ok:true });
});

// Upload bail
app.post("/api/tenants/:id/lease", authMiddleware, upload.single("file"), (req,res)=>{
  const mem = currentMembership(req);
  const id = Number(req.params.id);
  if (!req.file) return res.status(400).json({ error:"Fichier manquant" });
  const base = `${Date.now()}_${uuidv4()}_${(req.file.originalname||"file").replace(/[^\w.\-]/g,"_")}`;
  const p = path.join(FILES_DIR, base);
  const data = encryptBuffer(req.file.buffer);
  fs.writeFileSync(p, data);
  db.prepare("UPDATE tenants SET lease_path=?, lease_uploaded_at=? WHERE org_id=? AND id=?")
    .run(p, new Date().toISOString(), mem.org_id, id);
  res.json({ ok:true, url: `/api/files/${base}` });
});

// Pièces jointes
app.post("/api/tenants/:id/files", authMiddleware, upload.single("file"), (req,res)=>{
  const mem = currentMembership(req);
  const id = Number(req.params.id);
  if (!req.file) return res.status(400).json({ error:"Fichier manquant" });
  const base = `${Date.now()}_${uuidv4()}_${(req.file.originalname||"file").replace(/[^\w.\-]/g,"_")}`;
  const p = path.join(FILES_DIR, base);
  const data = encryptBuffer(req.file.buffer);
  fs.writeFileSync(p, data);
  const info = db.prepare(`
    INSERT INTO tenant_files(org_id,user_id,tenant_id,label,file_path,uploaded_at)
    VALUES(?,?,?,?,?,?)
  `).run(mem.org_id, req.user.id, id, (req.body.label||"").trim(), p, new Date().toISOString());
  res.json({ ok:true, id: info.lastInsertRowid, url:`/api/files/${base}` });
});
app.delete("/api/tenants/:tid/files/:fid", authMiddleware, (req,res)=>{
  const mem = currentMembership(req);
  const tid = Number(req.params.tid);
  const fid = Number(req.params.fid);
  const row = db.prepare("SELECT * FROM tenant_files WHERE org_id=? AND id=? AND tenant_id=?")
    .get(mem.org_id, fid, tid);
  if (row?.file_path && fs.existsSync(row.file_path)) { try { fs.unlinkSync(row.file_path); } catch {} }
  db.prepare("DELETE FROM tenant_files WHERE org_id=? AND id=? AND tenant_id=?").run(mem.org_id, fid, tid);
  res.json({ ok:true });
});

// ----------------- Invoices -----------------
function invoiceRowWithTenant(inv){
  const t = db.prepare("SELECT name FROM tenants WHERE id=?").get(inv.tenant_id);
  return { ...inv, tenant_name: t?.name || null,
           amount_usdc: inv.amount_usdc_micro ? inv.amount_usdc_micro / 1_000_000 : null };
}
app.get("/api/invoices", authMiddleware, (req,res)=>{
  const mem = currentMembership(req);
  const rows = db.prepare("SELECT * FROM invoices WHERE org_id=? ORDER BY id DESC").all(mem.org_id)
    .map(invoiceRowWithTenant);
  res.json(rows);
});
app.post("/api/invoices", authMiddleware, (req,res)=>{
  const mem = currentMembership(req);
  const { tenant_id, currency, expected_eur_cents, amount_usdc, due_date } = req.body || {};
  if (!tenant_id || !currency) return res.status(400).json({ error:"Paramètres invalides" });

  let expCents = null, usdcMicro = null;
  if (currency === "EUR") {
    if (!Number.isFinite(Number(expected_eur_cents))) return res.status(400).json({ error:"Montant EUR invalide" });
    expCents = Math.round(Number(expected_eur_cents));
  } else if (currency === "USDC") {
    const val = Number(amount_usdc);
    if (!isFinite(val)) return res.status(400).json({ error:"Montant USDC invalide" });
    usdcMicro = Math.round(val * 1_000_000);
  } else return res.status(400).json({ error:"Devise non supportée" });

  const info = db.prepare(`
    INSERT INTO invoices(org_id,user_id,tenant_id,currency,expected_eur_cents,amount_usdc_micro,status,due_date,reference)
    VALUES(?,?,?,?,?,?, 'En attente', ?, NULL)
  `).run(mem.org_id, req.user.id, tenant_id, currency, expCents, usdcMicro, due_date || null);

  const ref = `RC-${mem.org_id}-${info.lastInsertRowid}`;
  db.prepare("UPDATE invoices SET reference=? WHERE id=?").run(ref, info.lastInsertRowid);

  res.json({ id: info.lastInsertRowid, reference: ref });
});

app.post("/api/invoices/generate-next-month", authMiddleware, (req,res)=>{
  const mem = currentMembership(req);
  const today = new Date();
  const next = new Date(today.getFullYear(), today.getMonth()+1, 5);
  const due = next.toISOString().slice(0,10);

  const tenants = db.prepare("SELECT id FROM tenants WHERE org_id=? AND deleted_at IS NULL").all(mem.org_id);
  let created = 0;
  for (const t of tenants) {
    const lastEUR = db.prepare(`
      SELECT * FROM invoices WHERE org_id=? AND tenant_id=? AND currency='EUR'
      ORDER BY id DESC LIMIT 1
    `).get(mem.org_id, t.id);
    const lastUSDC = db.prepare(`
      SELECT * FROM invoices WHERE org_id=? AND tenant_id=? AND currency='USDC'
      ORDER BY id DESC LIMIT 1
    `).get(mem.org_id, t.id);

    if (lastEUR?.expected_eur_cents > 0) {
      const info = db.prepare(`
        INSERT INTO invoices(org_id,user_id,tenant_id,currency,expected_eur_cents,amount_usdc_micro,status,due_date,reference)
        VALUES(?,?,?,?,NULL,'En attente',?,NULL)
      `).run(mem.org_id, req.user.id, t.id, "EUR", lastEUR.expected_eur_cents, due);
      const ref = `RC-${mem.org_id}-${info.lastInsertRowid}`;
      db.prepare("UPDATE invoices SET reference=? WHERE id=?").run(ref, info.lastInsertRowid);
      created++;
    } else if (lastUSDC?.amount_usdc_micro > 0) {
      const info = db.prepare(`
        INSERT INTO invoices(org_id,user_id,tenant_id,currency,expected_eur_cents,amount_usdc_micro,status,due_date,reference)
        VALUES(?, ?, ?, 'USDC', NULL, ?, 'En attente', ?, NULL)
      `).run(mem.org_id, req.user.id, t.id, lastUSDC.amount_usdc_micro, due);
      const ref = `RC-${mem.org_id}-${info.lastInsertRowid}`;
      db.prepare("UPDATE invoices SET reference=? WHERE id=?").run(ref, info.lastInsertRowid);
      created++;
    }
  }
  res.json({ created, due_date: due });
});

// PDF reçu
app.get("/api/invoices/:id/receipt.pdf", authMiddleware, (req,res)=>{
  const mem = currentMembership(req);
  const id = Number(req.params.id);
  const inv = db.prepare("SELECT * FROM invoices WHERE org_id=? AND id=?").get(mem.org_id, id);
  if (!inv) return res.status(404).send("Not found");
  const t = db.prepare("SELECT name,unit FROM tenants WHERE id=?").get(inv.tenant_id);

  const doc = new PDFDocument({ margin: 36 });
  res.setHeader("Content-Type","application/pdf");
  doc.pipe(res);

  doc.fontSize(18).text("Facture / Reçu de paiement", { align:"center" }).moveDown();
  doc.fontSize(12).text(`Facture: INV-${inv.id}`);
  if (inv.reference) doc.text(`Référence virement: ${inv.reference}`);
  if (t) doc.text(`Locataire: ${t.name}${t.unit ? " — " + t.unit : ""}`);
  doc.text(`Devise: ${inv.currency}`);
  if (inv.currency === "EUR") doc.text(`Montant: ${(inv.expected_eur_cents/100).toFixed(2)} €`);
  else doc.text(`Montant: ${(inv.amount_usdc_micro/1_000_000).toFixed(6)} USDC`);
  if (inv.due_date) doc.text(`Échéance: ${inv.due_date}`);
  doc.text(`Statut: ${inv.status}`);
  if (inv.paid_at) doc.text(`Payé le: ${inv.paid_at}`);
  doc.end();
});

app.post("/api/invoices/:id/reset", authMiddleware, (req,res)=>{
  const mem = currentMembership(req);
  const id = Number(req.params.id);
  const inv = db.prepare("SELECT * FROM invoices WHERE org_id=? AND id=?").get(mem.org_id, id);
  if (!inv) return res.status(404).json({ error:"Facture introuvable" });
  db.prepare("UPDATE invoices SET status='En attente', paid_at=NULL WHERE org_id=? AND id=?")
    .run(mem.org_id, id);
  res.json({ ok:true });
});

// ----------------- Dashboard / Audit -----------------
app.get("/api/dashboard", authMiddleware, (req,res)=>{
  const mem = currentMembership(req);
  const rows = db.prepare("SELECT * FROM invoices WHERE org_id=? ORDER BY id DESC").all(mem.org_id)
    .map(invoiceRowWithTenant);
  res.json(rows);
});
app.get("/api/audit", authMiddleware, (req,res)=>{
  const limit = Math.max(1, Math.min(1000, Number(req.query.limit || 200)));
  const userId = req.query.user_id ? Number(req.query.user_id) : null;
  const rows = userId
    ? db.prepare("SELECT * FROM audit_logs WHERE user_id=? ORDER BY id DESC LIMIT ?").all(userId, limit)
    : db.prepare("SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?").all(limit);
  res.json(rows);
});

// ----------------- Banque -----------------
app.get("/api/payments/bank", authMiddleware, (req,res)=>{
  const mem = currentMembership(req);
  const bank = db.prepare("SELECT * FROM bank_transactions WHERE org_id=? ORDER BY id DESC").all(mem.org_id);
  const pending = db.prepare("SELECT * FROM invoices WHERE org_id=? AND status='En attente' AND currency='EUR' ORDER BY id ASC")
    .all(mem.org_id).map(invoiceRowWithTenant);
  res.json({ bank, pending_invoices: pending });
});

app.post("/api/payments/bank/import", authMiddleware, upload.single("file"), (req,res)=>{
  const mem = currentMembership(req);
  if (!req.file) return res.status(400).json({ error:"CSV manquant" });
  const text = req.file.buffer.toString("utf8");
  let rows;
  try{
    rows = parseCSV(text, { columns:true, skip_empty_lines:true, relax_column_count:true });
  }catch(e){ return res.status(400).json({ error:"CSV invalide" }); }

  let imported = 0;
  const now = new Date().toISOString();
  for (const r of rows) {
    const tx_date = String(r.date || r.Date || r["Transaction Date"] || r["Date opération"] || "").trim();
    const reference = String(r.reference || r.label || r["Libellé"] || r["Description"] || "").trim();
    const amt = Number(String(r.amount || r.Amount || r["Montant"] || r["Amount (EUR)"] || "0").replace(",", "."));
    if (!tx_date || !isFinite(amt)) continue;

    db.prepare(`
      INSERT INTO bank_transactions(org_id, tx_date, amount_eur_cents, counterparty, reference, raw_json, created_at)
      VALUES(?,?,?,?,?,?,?)
    `).run(mem.org_id, tx_date, Math.round(amt*100), null, reference, JSON.stringify(r), now);
    imported++;
  }
  res.json({ imported });
});

// auto-match EUR
function tryAutoMatchEUR(org_id){
  const pend = db.prepare("SELECT * FROM invoices WHERE org_id=? AND status='En attente' AND currency='EUR'").all(org_id);
  if (pend.length === 0) return { matched: 0 };
  const txs = db.prepare("SELECT * FROM bank_transactions WHERE org_id=? AND matched_invoice_id IS NULL").all(org_id);

  let matched = 0;
  for (const t of txs) {
    if (!t.reference) continue;
    const hit = pend.find(i => i.reference && t.reference.toLowerCase().includes(i.reference.toLowerCase()));
    if (!hit) continue;
    db.prepare("UPDATE invoices SET status='Payé', paid_at=? WHERE id=?").run(new Date().toISOString(), hit.id);
    db.prepare("UPDATE bank_transactions SET matched_invoice_id=? WHERE id=?").run(hit.id, t.id);
    matched++;
  }
  for (const t of txs) {
    if (t.matched_invoice_id) continue;
    const hit = pend.find(i => Math.abs(i.expected_eur_cents - t.amount_eur_cents) <= 100);
    if (!hit) continue;
    db.prepare("UPDATE invoices SET status='Payé', paid_at=? WHERE id=?").run(new Date().toISOString(), hit.id);
    db.prepare("UPDATE bank_transactions SET matched_invoice_id=? WHERE id=?").run(hit.id, t.id);
    matched++;
  }
  return { matched };
}

app.post("/api/payments/bank/auto-match", authMiddleware, (req,res)=>{
  const mem = currentMembership(req);
  const { matched } = tryAutoMatchEUR(mem.org_id);
  res.json({ matched });
});

app.post("/api/payments/bank/reconcile", authMiddleware, (req,res)=>{
  const mem = currentMembership(req);
  const { tx_id, invoice_id } = req.body || {};
  const t = db.prepare("SELECT * FROM bank_transactions WHERE org_id=? AND id=?").get(mem.org_id, Number(tx_id));
  const inv = db.prepare("SELECT * FROM invoices WHERE org_id=? AND id=?").get(mem.org_id, Number(invoice_id));
  if (!t || !inv) return res.status(400).json({ error:"Transaction ou facture introuvable" });

  db.prepare("UPDATE invoices SET status='Payé', paid_at=? WHERE id=?").run(new Date().toISOString(), inv.id);
  db.prepare("UPDATE bank_transactions SET matched_invoice_id=? WHERE id=?").run(inv.id, t.id);
  res.json({ ok:true });
});

// ----------------- Open banking (mock) -----------------
app.post("/api/bank/link-token", authMiddleware, (req,res)=>{
  const mem = currentMembership(req);
  const provider = OPENBANKING_PROVIDER;
  const fakePublicToken = `mock_public_${uuidv4()}`;
  res.json({ provider, link_token: fakePublicToken });
});
app.post("/api/bank/exchange", authMiddleware, (req,res)=>{
  const mem = currentMembership(req);
  const { public_token, provider } = req.body || {};
  if (!public_token) return res.status(400).json({ error:"public_token requis" });
  const enc = encryptString(`provider=${provider||OPENBANKING_PROVIDER};token=${public_token}`);
  const now = new Date().toISOString();
  db.prepare(`
    INSERT INTO bank_links(org_id,provider,access_token_enc,cursor,status,created_at,updated_at)
    VALUES(?,?,?,?, 'active', ?, ?)
  `).run(mem.org_id, (provider||OPENBANKING_PROVIDER), enc, null, now, now);
  res.json({ ok:true });
});
app.post("/api/bank/sync", authMiddleware, (req,res)=>{
  const mem = currentMembership(req);
  const links = db.prepare("SELECT * FROM bank_links WHERE org_id=? AND status='active'").all(mem.org_id);
  if (links.length === 0) return res.json({ synced:false, imported:0, matched:0 });

  let imported = 0;
  if ((process.env.OPENBANKING_PROVIDER||"mock").toLowerCase() === "mock") {
    const now = new Date().toISOString().slice(0,10);
    const rnd = Math.floor(Math.random()*3);
    for (let k=0;k<rnd;k++){
      const amtCents = [50000, 65000, 80000][Math.floor(Math.random()*3)];
      const ref = Math.random()<0.5 ? `LOYER ${now} RC-${mem.org_id}-${Math.max(1, Math.floor(Math.random()*20))}` : `LOYER ${now}`;
      db.prepare(`
        INSERT INTO bank_transactions(org_id, tx_date, amount_eur_cents, counterparty, reference, raw_json, created_at)
        VALUES(?,?,?,?,?,?,?)
      `).run(mem.org_id, now, amtCents, "Locataire", ref, JSON.stringify({ mock:true }), new Date().toISOString());
      imported++;
    }
  }
  const { matched } = tryAutoMatchEUR(mem.org_id);
  res.json({ synced:true, imported, matched });
});

// ----------------- Crypto (USDC) -----------------
app.get("/api/payments/crypto", authMiddleware, (req,res)=>{
  const mem = currentMembership(req);
  const cryptoRows = db.prepare("SELECT * FROM crypto_payments WHERE org_id=? ORDER BY id DESC").all(mem.org_id)
    .map(r => ({ ...r, amount_usdc: r.amount_usdc_micro/1_000_000 }));
  const pendingUSDC = db.prepare("SELECT * FROM invoices WHERE org_id=? AND status='En attente' AND currency='USDC' ORDER BY id ASC")
    .all(mem.org_id).map(invoiceRowWithTenant);
  res.json({ crypto: cryptoRows, pending_usdc: pendingUSDC });
});

app.post("/api/crypto/ingest", authMiddleware, (req,res)=>{
  const mem = currentMembership(req);
  const { network="base", tx_hash="", amount_usdc, reference="" } = req.body || {};
  const val = Number(amount_usdc);
  if (!isFinite(val) || val <= 0) return res.status(400).json({ error:"Montant USDC invalide" });

  const info = db.prepare(`
    INSERT INTO crypto_payments(org_id, network, tx_hash, currency, amount_usdc_micro, reference, status, created_at)
    VALUES(?, ?, ?, 'USDC', ?, ?, 'received', ?)
  `).run(mem.org_id, network, tx_hash || `tx_${uuidv4()}`, Math.round(val*1_000_000), reference || null, new Date().toISOString());
  res.json({ id: info.lastInsertRowid });
});

function tryAutoMatchUSDC(org_id){
  const pend = db.prepare("SELECT * FROM invoices WHERE org_id=? AND status='En attente' AND currency='USDC'").all(org_id);
  if (pend.length === 0) return { matched: 0 };
  const pays = db.prepare("SELECT * FROM crypto_payments WHERE org_id=? AND matched_invoice_id IS NULL AND status='received'").all(org_id);

  let matched = 0;
  for (const p of pays) {
    if (!p.reference) continue;
    const hit = pend.find(i => i.reference && p.reference.toLowerCase().includes(i.reference.toLowerCase()));
    if (!hit) continue;
    db.prepare("UPDATE invoices SET status='Payé', paid_at=? WHERE id=?").run(new Date().toISOString(), hit.id);
    db.prepare("UPDATE crypto_payments SET matched_invoice_id=? WHERE id=?").run(hit.id, p.id);
    matched++;
  }
  for (const p of pays) {
    if (p.matched_invoice_id) continue;
    const hit = pend.find(i => Math.abs(i.amount_usdc_micro - p.amount_usdc_micro) <= 10_000); // ±0.01 USDC
    if (!hit) continue;
    db.prepare("UPDATE invoices SET status='Payé', paid_at=? WHERE id=?").run(new Date().toISOString(), hit.id);
    db.prepare("UPDATE crypto_payments SET matched_invoice_id=? WHERE id=?").run(hit.id, p.id);
    matched++;
  }
  return { matched };
}
app.post("/api/crypto/auto-match", authMiddleware, (req,res)=>{
  const mem = currentMembership(req);
  const { matched } = tryAutoMatchUSDC(mem.org_id);
  res.json({ matched });
});
app.post("/api/crypto/reconcile", authMiddleware, (req,res)=>{
  const mem = currentMembership(req);
  const { payment_id, invoice_id } = req.body || {};
  const p = db.prepare("SELECT * FROM crypto_payments WHERE org_id=? AND id=?").get(mem.org_id, Number(payment_id));
  const inv = db.prepare("SELECT * FROM invoices WHERE org_id=? AND id=?").get(mem.org_id, Number(invoice_id));
  if (!p || !inv) return res.status(400).json({ error:"Paiement ou facture introuvable" });
  db.prepare("UPDATE invoices SET status='Payé', paid_at=? WHERE id=?").run(new Date().toISOString(), inv.id);
  db.prepare("UPDATE crypto_payments SET matched_invoice_id=? WHERE id=?").run(inv.id, p.id);
  res.json({ ok:true });
});

// ----------------- Landing media -----------------
app.get("/api/site-media", (_req,res)=>{
  const rows = db.prepare("SELECT * FROM site_media ORDER BY id DESC").all()
    .map(r => ({ ...r, url: `/api/media/${path.basename(r.filename)}` }));
  res.json(rows);
});
app.post("/api/site-media", upload.array("files", 12), (req,res)=>{
  const files = req.files || [];
  const out = [];
  const now = new Date().toISOString();
  for (const f of files) {
    const base = `${Date.now()}_${uuidv4()}_${(f.originalname||"file").replace(/[^\w.\-]/g,"_")}`;
    const p = path.join(MEDIA_DIR, base);
    fs.writeFileSync(p, f.buffer);
    const info = db.prepare(`
      INSERT INTO site_media(filename,label,mime,size_bytes,uploaded_at)
      VALUES(?,?,?,?,?)
    `).run(p, null, f.mimetype||"", f.size||0, now);
    out.push({ id: info.lastInsertRowid, url:`/api/media/${base}` });
  }
  res.json(out);
});
app.delete("/api/site-media/:id", (req,res)=>{
  const id = Number(req.params.id);
  const row = db.prepare("SELECT * FROM site_media WHERE id=?").get(id);
  if (row?.filename && fs.existsSync(row.filename)) { try { fs.unlinkSync(row.filename); } catch {} }
  db.prepare("DELETE FROM site_media WHERE id=?").run(id);
  res.json({ ok:true });
});

// ----------------- Listen -----------------
app.listen(PORT, ()=>{
  console.log(`[rentchain] API listening on http://localhost:${PORT}`);
});
