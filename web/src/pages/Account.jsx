// src/pages/Account.jsx
import React, { useEffect, useState } from "react";

// --- Mini client pour endpoints sensibles + utilitaires généraux
const RAW = (import.meta.env.VITE_API_URL || "").trim();
const API_BASE = RAW
  ? (RAW.replace(/\/+$/,"").endsWith("/api") ? RAW.replace(/\/+$/,"") : `${RAW.replace(/\/+$/,"")}/api`)
  : "http://127.0.0.1:4000/api";

async function http(path, { method="GET", body, headers } = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
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
  if (!res.ok) throw new Error((data && data.error) ? data.error : (typeof data === "string" ? data : `HTTP ${res.status}`));
  return data;
}

const sensitiveApi = {
  status() { return http("/security/sensitive-password/status"); },
  set(newPwd, oldPwd) {
    return http("/security/sensitive-password", { method:"POST", body: oldPwd ? { password:newPwd, old_password:oldPwd } : { password:newPwd } });
  },
  reset(accountPwd, newPwd) {
    return http("/security/sensitive-password/reset", { method:"POST", body:{ account_password:accountPwd, password:newPwd } });
  },
};

// --- (Optionnel) endpoints généraux utilisés ici
async function getMe(){ return http("/me"); }
async function getBillingInvoices(){
  // si pas d’endpoint dédié côté back, laissez vide. Ici on essaie et on tolère l’échec.
  try { return (await http("/billing/invoices")) || []; } catch { return []; }
}
async function createCheckout(plan){
  const j = await http("/stripe/checkout", { method:"POST", body:{ plan } });
  return j?.url;
}
async function openPortalUrl(){
  const j = await http("/stripe/portal", { method:"POST" });
  return j?.url;
}

export default function Account() {
  const [me, setMe] = useState(null);
  const [invoices, setInvoices] = useState([]);
  const [loading, setLoading] = useState(true);

  // mot de passe sensible
  const [sensDefined, setSensDefined] = useState(false);
  const [sensBusy, setSensBusy] = useState(false);
  const [oldPwd, setOldPwd] = useState("");
  const [newPwd, setNewPwd] = useState("");
  const [confirmPwd, setConfirmPwd] = useState("");

  // reset modal (sans UI complexe)
  const [showReset, setShowReset] = useState(false);
  const [accountPwd, setAccountPwd] = useState("");
  const [resetNew, setResetNew] = useState("");
  const [resetConfirm, setResetConfirm] = useState("");
  const [resetBusy, setResetBusy] = useState(false);

  async function load() {
    setLoading(true);
    try{
      const [u, inv, st] = await Promise.all([
        getMe().catch(()=>null),
        getBillingInvoices().catch(()=>[]),
        sensitiveApi.status().catch(()=>({ defined:false })),
      ]);
      if (u) setMe(u);
      setInvoices(Array.isArray(inv)?inv:[]);
      setSensDefined(!!(st?.defined));
    } finally {
      setLoading(false);
    }
  }
  useEffect(()=>{ load(); }, []);

  async function onSaveSensitive(e){
    e.preventDefault();
    if (!newPwd || newPwd.length < 6) { alert("Mot de passe sensible : 6 caractères minimum"); return; }
    if (newPwd !== confirmPwd) { alert("Les deux entrées ne correspondent pas"); return; }
    setSensBusy(true);
    try{
      await sensitiveApi.set(newPwd, sensDefined ? oldPwd : undefined);
      setOldPwd(""); setNewPwd(""); setConfirmPwd("");
      alert(sensDefined ? "Mot de passe sensible modifié" : "Mot de passe sensible défini");
      await load();
    } catch(e){ alert(e.message || "Erreur"); }
    finally { setSensBusy(false); }
  }

  async function onReset(e){
    e.preventDefault();
    if (!accountPwd) { alert("Mot de passe de compte requis"); return; }
    if (!resetNew || resetNew.length < 6) { alert("Nouveau mot de passe sensible : 6 caractères minimum"); return; }
    if (resetNew !== resetConfirm) { alert("Les deux entrées ne correspondent pas"); return; }
    setResetBusy(true);
    try{
      await sensitiveApi.reset(accountPwd, resetNew);
      setAccountPwd(""); setResetNew(""); setResetConfirm(""); setShowReset(false);
      alert("Mot de passe sensible réinitialisé");
      await load();
    } catch(e){ alert(e.message || "Erreur"); }
    finally { setResetBusy(false); }
  }

  async function goCheckout(plan){
    try{
      const url = await createCheckout(plan);
      if (url) location.href = url;
    }catch(e){ alert(e.message || "Erreur Checkout"); }
  }
  async function openPortal(){
    try{
      const url = await openPortalUrl();
      if (url) location.href = url;
    }catch(e){ alert(e.message || "Erreur Billing Portal"); }
  }

  if (loading) return <div className="p-4">Chargement…</div>;

  const plan = me?.plan || "FREE";
  const status = me?.subscription_status || "inactive";
  const quotas = me?.quotas || { properties:0, tenants:0, storageMB:0 };

  return (
    <div className="max-w-5xl mx-auto p-4 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">Mon compte</h1>
          <div className="text-sm text-gray-600">Plan : <b>{plan}</b> — statut : {status}</div>
          <div className="text-sm text-gray-600 mt-1">Quotas : {quotas.properties} immeuble(s) • {quotas.tenants} locataire(s) • {quotas.storageMB} Mo</div>
        </div>
        <div className="flex gap-2">
          <button onClick={openPortal} className="border rounded px-3 py-1.5 hover:bg-gray-50">Billing Portal</button>
        </div>
      </div>

      <div className="grid sm:grid-cols-3 gap-4">
        <div className="rounded-xl border p-4">
          <div className="text-sm text-gray-500">FREE</div>
          <div className="text-3xl font-bold mt-1">0 €</div>
          <button className="mt-3 w-full border rounded px-3 py-2" disabled>Plan en cours</button>
        </div>
        <div className="rounded-xl border p-4 ring-2 ring-blue-600">
          <div className="text-sm text-gray-500">PRO</div>
          <div className="text-3xl font-bold mt-1">49 €</div>
          <button onClick={()=>goCheckout("PRO")} className="mt-3 w-full border rounded px-3 py-2 hover:bg-gray-50">Passer en PRO</button>
        </div>
        <div className="rounded-xl border p-4">
          <div className="text-sm text-gray-500">AGENCY</div>
          <div className="text-3xl font-bold mt-1">199 €</div>
          <button onClick={()=>goCheckout("AGENCY")} className="mt-3 w-full border rounded px-3 py-2 hover:bg-gray-50">Passer en AGENCY</button>
        </div>
      </div>

      <div className="rounded border p-4">
        <div className="font-semibold mb-2">Mot de passe pour actions sensibles</div>
        <div className="text-xs mb-3">
          Évite les suppressions/validations accidentelles. Statut :{" "}
          <span className={`px-2 py-0.5 rounded ${sensDefined ? "bg-green-100 text-green-700" : "bg-gray-100"}`}>
            {sensDefined ? "Déjà défini" : "Non défini"}
          </span>
        </div>

        <form onSubmit={onSaveSensitive} className="grid sm:grid-cols-2 gap-3">
          {sensDefined && (
            <input type="password" placeholder="Ancien mot de passe sensible" value={oldPwd} onChange={e=>setOldPwd(e.target.value)} className="rounded border px-3 py-2" autoComplete="current-password" />
          )}
          <input type="password" placeholder="Nouveau mot de passe sensible" value={newPwd} onChange={e=>setNewPwd(e.target.value)} className="rounded border px-3 py-2" autoComplete="new-password" />
          <input type="password" placeholder="Confirmer" value={confirmPwd} onChange={e=>setConfirmPwd(e.target.value)} className="rounded border px-3 py-2" autoComplete="new-password" />
          <div className="sm:col-span-2 flex items-center gap-2">
            <button disabled={sensBusy} className="rounded bg-black text-white px-4 py-2 disabled:opacity-60">
              {sensBusy ? "Enregistrement…" : sensDefined ? "Modifier" : "Enregistrer"}
            </button>
            {sensDefined && (
              <button type="button" onClick={()=>setShowReset(true)} className="rounded border px-4 py-2 hover:bg-gray-50">
                Mot de passe oublié ?
              </button>
            )}
          </div>
        </form>

        {showReset && (
          <div className="mt-4 border rounded p-3">
            <div className="font-semibold mb-2">Réinitialiser (via mot de passe de compte)</div>
            <form onSubmit={onReset} className="grid sm:grid-cols-2 gap-3">
              <input type="password" placeholder="Mot de passe du compte" value={accountPwd} onChange={e=>setAccountPwd(e.target.value)} className="rounded border px-3 py-2" />
              <input type="password" placeholder="Nouveau mot de passe sensible" value={resetNew} onChange={e=>setResetNew(e.target.value)} className="rounded border px-3 py-2" />
              <input type="password" placeholder="Confirmer" value={resetConfirm} onChange={e=>setResetConfirm(e.target.value)} className="rounded border px-3 py-2" />
              <div className="sm:col-span-2 flex gap-2">
                <button type="button" onClick={()=>setShowReset(false)} className="border rounded px-4 py-2">Annuler</button>
                <button disabled={resetBusy} className="rounded bg-black text-white px-4 py-2 disabled:opacity-60">
                  {resetBusy ? "En cours…" : "Réinitialiser"}
                </button>
              </div>
            </form>
          </div>
        )}
      </div>

      <div className="rounded border p-4">
        <div className="font-semibold mb-2">Vos factures SaaS</div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-gray-50">
              <tr>
                <th className="text-left p-2">Date</th>
                <th className="text-left p-2">Numéro</th>
                <th className="text-left p-2">Montant</th>
                <th className="text-left p-2">Statut</th>
                <th className="text-right p-2">Liens</th>
              </tr>
            </thead>
            <tbody>
              {invoices.map(i => (
                <tr key={i.id} className="border-t">
                  <td className="p-2">{new Date(i.created).toLocaleString()}</td>
                  <td className="p-2">{i.number || i.id}</td>
                  <td className="p-2">{(i.amount_due/100).toFixed(2)} {i.currency}</td>
                  <td className="p-2">{i.status}</td>
                  <td className="p-2 text-right">
                    {i.hosted_invoice_url && <a href={i.hosted_invoice_url} target="_blank" rel="noreferrer" className="border rounded px-2 py-1 hover:bg-gray-50">Portail</a>}
                    {i.invoice_pdf && <a href={i.invoice_pdf} target="_blank" rel="noreferrer" className="border rounded px-2 py-1 hover:bg-gray-50 ml-2">PDF</a>}
                  </td>
                </tr>
              ))}
              {invoices.length===0 && <tr><td colSpan={5} className="p-3 text-gray-500">Aucune facture.</td></tr>}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
