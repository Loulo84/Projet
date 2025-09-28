// server/routes/secondary.js
const express = require("express");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const router = express.Router();

const TTL_SEC = 5 * 60;
const SECRET = process.env.SEC_CONFIRM_SECRET || "DEV_CHANGE_ME";

function genSalt(n=16){return crypto.randomBytes(n).toString("hex");}
function hash(pw, salt){return crypto.pbkdf2Sync(pw, salt, 120000, 64, "sha512").toString("hex");}
function eqHex(a,b){
  const A = Buffer.from(a||"", "hex"), B = Buffer.from(b||"", "hex");
  if (A.length !== B.length) return false;
  return crypto.timingSafeEqual(A,B);
}

// besoin que req.user et req.db existent (ton index.js ci-dessous les ajoute)
router.get("/status", async (req,res)=>{
  const u = await req.db.get(`SELECT secondary_password_hash hash, secondary_password_salt salt, secondary_enabled enabled FROM users WHERE id=?`, [req.user.id]);
  res.json({ enabled: !!(u && u.enabled), hasHash: !!(u && u.hash) });
});

router.post("/set", async (req,res)=>{
  const { newPasswordSecondary, currentPasswordSecondary } = req.body||{};
  if (!newPasswordSecondary || newPasswordSecondary.length < 8) return res.status(400).json({error:"≥ 8 caractères"});
  const row = await req.db.get(`SELECT secondary_password_hash hash, secondary_password_salt salt, secondary_enabled enabled FROM users WHERE id=?`, [req.user.id]);
  if (row && row.enabled) {
    const ok = eqHex(hash(currentPasswordSecondary||"", row.salt), row.hash||"");
    if (!ok) return res.status(401).json({error:"Ancien mot de passe invalide"});
  }
  const salt = genSalt();
  await req.db.run(`UPDATE users SET secondary_password_hash=?, secondary_password_salt=?, secondary_enabled=1, secondary_updated_at=datetime('now') WHERE id=?`,
    [hash(newPasswordSecondary, salt), salt, req.user.id]);
  res.json({ok:true, enabled:true});
});

router.post("/disable", async (req,res)=>{
  const { passwordSecondary } = req.body||{};
  const row = await req.db.get(`SELECT secondary_password_hash hash, secondary_password_salt salt, secondary_enabled enabled FROM users WHERE id=?`, [req.user.id]);
  if (!row || !row.enabled) return res.json({ok:true, enabled:false});
  const ok = eqHex(hash(passwordSecondary||"", row.salt), row.hash||"");
  if (!ok) return res.status(401).json({error:"Mot de passe invalide"});
  await req.db.run(`UPDATE users SET secondary_password_hash=NULL, secondary_password_salt=NULL, secondary_enabled=0 WHERE id=?`, [req.user.id]);
  res.json({ok:true, enabled:false});
});

router.post("/confirm", async (req,res)=>{
  const { passwordSecondary, scope } = req.body||{};
  if (!scope) return res.status(400).json({error:"scope manquant"});
  const row = await req.db.get(`SELECT secondary_password_hash hash, secondary_password_salt salt, secondary_enabled enabled FROM users WHERE id=?`, [req.user.id]);
  if (!row || !row.enabled) return res.status(400).json({error:"non configuré"});
  const ok = eqHex(hash(passwordSecondary||"", row.salt), row.hash||"");
  if (!ok) return res.status(401).json({error:"Mot de passe invalide"});
  const token = jwt.sign({uid:req.user.id, scope}, SECRET, {expiresIn: TTL_SEC});
  res.json({ok:true, token, ttl:TTL_SEC});
});

// middleware réutilisable
function requireSecondary(scope){
  return (req,res,next)=>{
    const t = req.headers["x-secondary-confirm"];
    if (!t) return res.status(401).json({error:"Confirmation requise"});
    try {
      const p = jwt.verify(t, SECRET);
      if (p.uid !== req.user.id || p.scope !== scope) return res.status(401).json({error:"Token invalide"});
      next();
    } catch { return res.status(401).json({error:"Token expiré/invalide"}); }
  };
}
router.requireSecondary = requireSecondary;

module.exports = router;
