// C:\Projet\server\sensitive-actions.js
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const STEP_UP_TTL = Number(process.env.STEP_UP_TTL || 300); // 5 minutes

module.exports = function mountSensitive({ app, db, secret, authMiddleware, logAudit }) {
  // -------- Helpers locales --------
  function getSensitiveHash() {
    const r = db.prepare("SELECT value FROM settings WHERE key='sensitive_password_hash'").get();
    return r?.value || "";
  }
  function setSensitiveHash(hash) {
    db.prepare(`
      INSERT INTO settings(key,value) VALUES('sensitive_password_hash',?)
      ON CONFLICT(key) DO UPDATE SET value=excluded.value
    `).run(hash);
  }
  function signStepUp(userId) {
    const exp = Math.floor(Date.now()/1000) + STEP_UP_TTL;
    const stepUpToken = jwt.sign({ typ:"stepup_sensitive", sub:String(userId), exp }, secret);
    return { stepUpToken, exp };
  }
  function verifyStepUp(req, res, next) {
    try {
      const tok = String(req.headers.authorization || "").replace(/^Bearer\s+/i, "");
      if (!tok) return res.status(401).json({ error: "step-up requis" });
      const p = jwt.verify(tok, secret);
      if (p.typ !== "stepup_sensitive") throw new Error("typ");
      if (String(p.sub) !== String(req.user?.id)) throw new Error("sub");
      next();
    } catch {
      return res.status(401).json({ error: "step-up invalide/expiré" });
    }
  }

  // Pour compatibilité (si la colonne existe)
  function setCashFlag(invId, orgId, flag) {
    try {
      db.prepare("UPDATE invoices SET paid_via_cash=? WHERE id=? AND org_id=?").run(flag ? 1 : 0, invId, orgId);
    } catch {}
  }

  // -------- Routes publiques / protégées --------
  app.get("/api/security/_ping", (_req, res) => res.json({ ok:true }));

  // Statut : défini ou pas
  app.get("/api/security/sensitive-password/status", authMiddleware, (req, res) => {
    const has = !!getSensitiveHash();
    res.json({ defined: has });
  });

  // Définir / modifier
  app.post("/api/security/sensitive-password", authMiddleware, async (req, res) => {
    const { password, old_password } = req.body || {};
    if (!password || String(password).length < 6) return res.status(400).json({ error:"Mot de passe trop court" });

    const current = getSensitiveHash();
    if (!current) {
      // première définition
      const hash = await bcrypt.hash(String(password), 10);
      setSensitiveHash(hash);
      logAudit(req.user.id, "sensitive_set", req);
      return res.json({ ok:true });
    }

    // modification => vérifier l'ancien
    if (!old_password) return res.status(400).json({ error:"Ancien mot de passe requis" });
    const ok = await bcrypt.compare(String(old_password), current);
    if (!ok) return res.status(400).json({ error:"Ancien mot de passe invalide" });

    const hash = await bcrypt.hash(String(password), 10);
    setSensitiveHash(hash);
    logAudit(req.user.id, "sensitive_change", req);
    res.json({ ok:true });
  });

  // Reset via mot de passe de compte
  app.post("/api/security/sensitive-password/reset", authMiddleware, async (req, res) => {
    const { account_password, password } = req.body || {};
    if (!account_password || !password) return res.status(400).json({ error:"Champs requis" });

    const u = db.prepare("SELECT * FROM users WHERE id=?").get(req.user.id);
    const ok = await bcrypt.compare(String(account_password), u?.password_hash || "");
    if (!ok) return res.status(400).json({ error:"Mot de passe de compte invalide" });

    const hash = await bcrypt.hash(String(password), 10);
    setSensitiveHash(hash);
    logAudit(req.user.id, "sensitive_reset", req);
    res.json({ ok:true });
  });

  // Step-up → jeton court
  app.post("/api/auth/step-up-sensitive", authMiddleware, async (req, res) => {
    const { password } = req.body || {};
    const current = getSensitiveHash();
    if (!current) return res.status(400).json({ error:"non défini" });
    const ok = await bcrypt.compare(String(password||""), current);
    if (!ok) return res.status(401).json({ error:"Mot de passe sensible invalide" });

    const payload = signStepUp(req.user.id);
    logAudit(req.user.id, "sensitive_stepup", req);
    res.json(payload); // { stepUpToken, exp }
  });

  // -------- Paiement cash (actions sensibles) --------
  // mark
  app.post("/api/payments/cash/mark", authMiddleware, verifyStepUp, (req, res) => {
    const { invoice_id } = req.body || {};
    if (!invoice_id) return res.status(400).json({ error:"invoice_id requis" });
    const mem = currentMembership(req);
    if (!mem) return res.status(403).json({ error:"Organisation introuvable" });

    const inv = db.prepare("SELECT * FROM invoices WHERE id=? AND org_id=?").get(Number(invoice_id), mem.org_id);
    if (!inv) return res.status(404).json({ error:"Facture introuvable" });

    db.prepare("UPDATE invoices SET status='Payé', paid_at=?, receipt_note=? WHERE id=? AND org_id=?")
      .run(new Date().toISOString(), "Payé (cash)", inv.id, mem.org_id);
    setCashFlag(inv.id, mem.org_id, true);

    logAudit(req.user.id, "cash_mark_paid", req, { invoice_id: inv.id });
    res.json({ ok:true });
  });

  // unmark
  app.post("/api/payments/cash/unmark", authMiddleware, verifyStepUp, (req, res) => {
    const { invoice_id } = req.body || {};
    if (!invoice_id) return res.status(400).json({ error:"invoice_id requis" });
    const mem = currentMembership(req);
    if (!mem) return res.status(403).json({ error:"Organisation introuvable" });

    const inv = db.prepare("SELECT * FROM invoices WHERE id=? AND org_id=?").get(Number(invoice_id), mem.org_id);
    if (!inv) return res.status(404).json({ error:"Facture introuvable" });

    db.prepare("UPDATE invoices SET status='En attente', paid_at=NULL, receipt_note=NULL WHERE id=? AND org_id=?")
      .run(inv.id, mem.org_id);
    setCashFlag(inv.id, mem.org_id, false);

    logAudit(req.user.id, "cash_unmark_paid", req, { invoice_id: inv.id });
    res.json({ ok:true });
  });

  // helper pour lire l’org courante depuis ton code existant
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

  console.log("[sensitive-actions] routes montées");
};
