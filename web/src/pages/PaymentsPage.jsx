// src/pages/PaymentsPage.jsx
import React, { useEffect, useMemo, useRef, useState } from "react";
import { api } from "@/api";
import { useToast } from "@/ui/Toast";
import { bus } from "@/lib/bus";

const MOIS_FR = ["janvier","février","mars","avril","mai","juin","juillet","août","septembre","octobre","novembre","décembre"];
const LS_PREFS = "rentchain.paymentPrefs.v1";
const LS_MONTH = "rentchain.payments.month";

function loadPrefs() { try { return JSON.parse(localStorage.getItem(LS_PREFS) || "{}"); } catch { return {}; } }
function prefOf(prefs, tenantId){ return prefs?.[tenantId] || { method:"bank", crypto_address:"" }; }

function fmtEUR(cents){ return (Number(cents||0)/100).toFixed(2) + " €"; }
function fmtUSDC(microOrNum){
  const n = Number(microOrNum||0);
  const micro = n >= 1_000_000 ? n : Math.round(n*1_000_000);
  return (micro/1_000_000).toFixed(6) + " USDC";
}
function ym(d){ return d.toISOString().slice(0,7); }
function ymToLabel(ymStr){
  const [y,m] = ymStr.split("-").map(Number);
  const name = MOIS_FR[(m-1+12)%12] || "";
  return `${ymStr} (${name})`;
}
function monthsForSelect() {
  const base = new Date();
  const list = [];
  for (let k=-3;k<=4;k++){
    const d = new Date(base.getFullYear(), base.getMonth()+k, 1);
    list.push(ym(d));
  }
  return list;
}

export default function PaymentsPage(){
  const toast = useToast();

  // ------- état
  const now = new Date();
  const [prefs, setPrefs] = useState(loadPrefs());
  const [month, setMonth] = useState(localStorage.getItem(LS_MONTH) || ym(now)); // YYYY-MM
  const [search, setSearch] = useState("");
  const [selectedTenantId, setSelectedTenantId] = useState(null);

  const [loading, setLoading] = useState(true);
  const [tenants, setTenants] = useState([]);
  const [invoices, setInvoices] = useState([]);
  const fileRef = useRef(null);

  // Historique (modal)
  const [showHistory, setShowHistory] = useState(false);

  // Step-up sensible (jeton court)
  const [stepUp, setStepUp] = useState({ token: null, exp: 0, countdown: 0 });
  const [showPwdModal, setShowPwdModal] = useState(false);
  const [pwd, setPwd] = useState("");
  const [pendingAction, setPendingAction] = useState(null); // { mode:'mark'|'unmark', inv }

  // ------- load
  async function loadAll(){
    setLoading(true);
    try{
      const [t, inv] = await Promise.all([
        api.listTenants().catch(()=>[]),
        api.listInvoices().catch(()=>[])
      ]);
      setTenants(Array.isArray(t) ? t : []);
      setInvoices(Array.isArray(inv) ? inv : []);
    } finally { setLoading(false); }
  }
  useEffect(()=>{ loadAll(); }, []);
  useEffect(() => {
    const onData = () => loadAll();
    bus.addEventListener("data-changed", onData);
    return () => bus.removeEventListener("data-changed", onData);
  }, []);
  useEffect(() => localStorage.setItem(LS_MONTH, month), [month]);

  // Countdown du jeton step-up
  useEffect(() => {
    if (!stepUp.token) return;
    const id = setInterval(() => {
      const left = Math.max(0, Math.floor(stepUp.exp - Date.now()/1000));
      setStepUp(s => ({ ...s, countdown: left }));
      if (left === 0) setStepUp({ token: null, exp: 0, countdown: 0 });
    }, 1000);
    return () => clearInterval(id);
  }, [stepUp.token, stepUp.exp]);

  // ------- dérivées
  const invByTenant = useMemo(()=>{
    const map = new Map(); // tenant_id -> array invoices
    (invoices||[]).forEach(i=>{
      const arr = map.get(i.tenant_id) || [];
      arr.push(i);
      map.set(i.tenant_id, arr);
    });
    for (const [k, arr] of map) arr.sort((a,b)=> (a.due_date||"").localeCompare(b.due_date||""));
    return map;
  }, [invoices]);

  const monthRows = useMemo(()=>{
    const rows = tenants
      .filter(t => {
        if (!search.trim()) return true;
        const q = search.trim().toLowerCase();
        return [t.name||"", t.address||"", t.unit||""].join(" ").toLowerCase().includes(q);
      })
      .map(t => {
        const all = invByTenant.get(t.id) || [];
        const cur = all.filter(i => (i.due_date||"").slice(0,7) === month);
        let eurDue=0, eurPaidPart=0, usdcDue=0, usdcPaidPart=0;
        const items = [];

        cur.forEach(i => {
          if (i.currency === "EUR") {
            const due = Number(i.expected_eur_cents || 0);
            const paid = Number(i.paid_eur_cents || 0);
            const rest = Math.max(due - paid, 0);
            eurDue += rest;
            if (paid > 0 && paid < due) eurPaidPart += paid;
          } else {
            const due = Number(i.amount_usdc_micro || 0);
            const paid = Number(i.paid_usdc_micro || 0);
            const rest = Math.max(due - paid, 0);
            usdcDue += rest;
            if (paid > 0 && paid < due) usdcPaidPart += paid;
          }
          items.push(i);
        });

        const ok = eurDue === 0 && usdcDue === 0 && items.length > 0;
        return { tenant: t, items, eurDue, eurPaidPart, usdcDue, usdcPaidPart, ok };
      })
      .sort((a,b) => (b.eurDue + b.usdcDue) - (a.eurDue + a.usdcDue));
    return rows;
  }, [tenants, invByTenant, month, search]);

  const totals = useMemo(
    () => monthRows.reduce((acc, r) => { acc.eur += r.eurDue; acc.usdc += r.usdcDue; return acc; }, { eur:0, usdc:0 }),
    [monthRows]
  );

  function setPref(tenantId, patch) {
    const next = { ...prefs, [tenantId]: { ...prefOf(prefs, tenantId), ...patch } };
    setPrefs(next); localStorage.setItem(LS_PREFS, JSON.stringify(next));
  }

  // ---- Actions rapides
  async function bankAuto(){ try{ await api.bankAutoMatch(); await loadAll(); toast?.success("Auto-match banque effectué."); }catch{ toast?.error("Auto-match impossible"); } }
  async function cryptoAuto(){ try{ await api.cryptoAutoMatch(); await loadAll(); toast?.success("Auto-match crypto effectué."); }catch{ toast?.error("Auto-match impossible"); } }

  // Step-up sensible: ouvre modale
  function askSensitive(mode, inv) {
    setPendingAction({ mode, inv });
    setPwd("");
    setShowPwdModal(true);
  }
  async function submitSensitivePassword(e) {
    e.preventDefault();
    try{
      const data = await api.stepUpSensitive(pwd); // { stepUpToken, exp }
      setStepUp({ token: data.stepUpToken, exp: data.exp, countdown: Math.max(0, Math.floor(data.exp - Date.now()/1000)) });
      setShowPwdModal(false);
      if (pendingAction) await runSensitiveAction(pendingAction.mode, pendingAction.inv, data.stepUpToken);
    }catch(err){
      const msg = err?.data?.error || err?.message || "Erreur step-up";
      if (/non défini/i.test(msg)) toast?.error("Mot de passe sensible non défini. Allez dans Compte → Mot de passe sensible.");
      else toast?.error(msg);
    }
  }

  async function runSensitiveAction(mode, inv, tokenOverride=null) {
    const token = tokenOverride || stepUp.token;
    if (!token) { askSensitive(mode, inv); return; }
    try{
      if (mode === "mark") await api.cashMark(inv.id, token);
      else await api.cashUnmark(inv.id, token);
      toast?.success(mode === "mark" ? "Marqué payé (cash)." : "Annulé (cash).");
      await loadAll();
    }catch(err){
      toast?.error(err?.data?.error || err?.message || "Action impossible");
    }
  }

  if (loading) return <div className="p-4">Chargement…</div>;

  return (
    <div className="max-w-6xl mx-auto p-4 space-y-4">
      <div className="flex items-center justify-between gap-3">
        <h1 className="text-2xl font-bold">Paiements</h1>
        <div className="flex items-center gap-2">
          {stepUp.token && (
            <span className="text-xs rounded-full px-2 py-0.5 bg-blue-50 text-blue-700">
              sécurisé {String(Math.max(0, stepUp.countdown)).padStart(2,"0")}s
            </span>
          )}
          <select value={month} onChange={(e)=>setMonth(e.target.value)} className="rounded border px-2 py-1.5 text-sm">
            {monthsForSelect().map(m => <option key={m} value={m}>{ymToLabel(m)}</option>)}
          </select>
        </div>
      </div>

      {/* Récap global (mois) */}
      <div className={`rounded-xl border p-3 text-sm ${totals.eur===0 && totals.usdc===0 ? "bg-green-50 border-green-200 text-green-800" : "bg-red-50 border-red-200 text-red-800"}`}>
        {totals.eur===0 && totals.usdc===0
          ? <div>✅ Tout est payé pour {ymToLabel(month)}.</div>
          : <div className="flex flex-wrap gap-3 items-center"><div className="font-medium">Reste à encaisser (mois) :</div><div>{fmtEUR(totals.eur)}</div><div>{fmtUSDC(totals.usdc)}</div></div>}
      </div>

      {/* Actions rapides */}
      <div className="rounded-xl border bg-white p-3 flex flex-wrap gap-2 items-center">
        <div className="font-medium">Actions rapides :</div>
        <button onClick={bankAuto} className="rounded border px-3 py-1.5 text-sm hover:bg-gray-50">Banque — Auto-match</button>
        <input ref={fileRef} type="file" accept=".csv,text/csv" className="hidden"
          onChange={async e => { const f=e.target.files?.[0]; e.target.value=""; if(!f) return;
            try{ await api.bankImportCSV(f); await bankAuto(); toast?.success("CSV importé"); await loadAll(); }
            catch(err){ toast?.error(err?.response?.data?.error||"Import impossible"); } }} />
        <button onClick={cryptoAuto} className="rounded border px-3 py-1.5 text-sm hover:bg-gray-50">Crypto — Auto-match</button>
      </div>

      {/* Vue du mois */}
      <section className="rounded-xl border bg-white p-4">
        <div className="mb-3">
          <div className="text-lg font-semibold">Vue du mois — {ymToLabel(month)}</div>
          <div className="text-sm text-gray-600">Rouge = reste à payer. Vert = tout est payé.</div>
        </div>

        <div className="mb-3 flex flex-wrap gap-2 items-center">
          <input className="rounded border px-3 py-2 text-sm w-72 max-w-full" placeholder="Rechercher un locataire…" value={search} onChange={(e)=>setSearch(e.target.value)} />
          <select className="rounded border px-3 py-2 text-sm" value={String(selectedTenantId||"")}
            onChange={(e)=>{ const id=e.target.value?Number(e.target.value):null; setSelectedTenantId(id); if(id) setShowHistory(true); }}>
            <option value="">— Ouvrir l’historique d’un locataire —</option>
            {tenants.map(t => <option key={t.id} value={t.id}>{t.name}</option>)}
          </select>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-gray-50">
              <tr>
                <th className="text-left p-2">Locataire</th>
                <th className="text-left p-2">Préférence</th>
                <th className="text-left p-2">Adresse crypto</th>
                <th className="text-left p-2">Reste EUR</th>
                <th className="text-left p-2">Reste USDC</th>
                <th className="text-left p-2">Statut</th>
                <th className="text-right p-2">Pièces / Actions</th>
              </tr>
            </thead>
            <tbody>
              {monthRows.map(({ tenant, items, eurDue, eurPaidPart, usdcDue, usdcPaidPart, ok }) => {
                const pref = prefOf(prefs, tenant.id);
                const hasDue = eurDue > 0 || usdcDue > 0;
                const showPartial = eurPaidPart > 0 || usdcPaidPart > 0;
                return (
                  <tr key={tenant.id} className="border-t align-top">
                    <td className="p-2">
                      <div className="flex items-start justify-between gap-2">
                        <div>
                          <button onClick={()=>{ setSelectedTenantId(tenant.id); setShowHistory(true); }}
                                  className="text-left font-medium underline-offset-2 hover:underline">
                            {tenant.name}
                          </button>
                          <div className="text-xs text-gray-500">{tenant.address || tenant.unit || "—"}</div>
                          {showPartial && (
                            <div className="text-xs mt-1 text-amber-700">
                              déjà payé (mois) : {eurPaidPart>0 && <b>{fmtEUR(eurPaidPart)}</b>} {usdcPaidPart>0 && <b> {fmtUSDC(usdcPaidPart)}</b>}
                            </div>
                          )}
                        </div>
                        <div className={`rounded-full px-2 py-0.5 text-xs font-medium ${hasDue ? "bg-red-100 text-red-800" : "bg-green-100 text-green-800"}`}>
                          {hasDue ? <>Reste: {fmtEUR(eurDue)} {fmtUSDC(usdcDue)}</> : "À jour"}
                        </div>
                      </div>
                    </td>

                    <td className="p-2">
                      <select className="rounded border px-2 py-1" value={pref.method} onChange={(e)=>setPref(tenant.id, { method:e.target.value })}>
                        <option value="bank">Banque</option>
                        <option value="crypto">Crypto</option>
                      </select>
                    </td>
                    <td className="p-2">
                      {pref.method === "crypto" ? (
                        <input className="w-64 max-w-full rounded border px-2 py-1" placeholder="Adresse de paiement (USDC)"
                               value={pref.crypto_address} onChange={(e)=>setPref(tenant.id,{ crypto_address:e.target.value })} />
                      ) : <span className="text-gray-400">—</span>}
                    </td>

                    <td className={`p-2 ${eurDue>0 ? "text-red-600 font-semibold" : "text-green-700"}`}>{fmtEUR(eurDue)}</td>
                    <td className={`p-2 ${usdcDue>0 ? "text-red-600 font-semibold" : "text-green-700"}`}>{fmtUSDC(usdcDue)}</td>
                    <td className="p-2">
                      <span className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium ${ok ? "bg-green-100 text-green-800" : "bg-red-100 text-red-800"}`}>
                        {ok ? "Payé" : "À payer"}
                      </span>
                    </td>

                    <td className="p-2 text-right">
                      <div className="flex gap-2 flex-wrap justify-end">
                        {items.map(i => {
                          const paid = (i.status||"") === "Payé" || !!i.paid_at;
                          return (
                            <div key={i.id} className="flex items-center gap-1">
                              <a href={api.receiptPdfUrl(i.id)} target="_blank" rel="noreferrer"
                                 className="inline-flex items-center gap-1 rounded border px-2 py-1 hover:bg-gray-50">INV-{i.id}</a>
                              {!paid ? (
                                <button onClick={()=>askSensitive("mark", i)} className="inline-flex items-center gap-1 rounded border px-2 py-1 hover:bg-gray-50 text-xs">
                                  cash
                                </button>
                              ) : (
                                i.paid_via_cash ? (
                                  <button onClick={()=>askSensitive("unmark", i)} className="inline-flex items-center gap-1 rounded border px-2 py-1 hover:bg-gray-50 text-xs">
                                    annuler cash
                                  </button>
                                ) : null
                              )}
                            </div>
                          );
                        })}
                        {items.length===0 && <span className="text-gray-400">—</span>}
                      </div>
                    </td>
                  </tr>
                );
              })}
              {monthRows.length===0 && <tr><td colSpan={7} className="p-3 text-gray-500">Aucun locataire.</td></tr>}
            </tbody>
          </table>
        </div>
      </section>

      {/* Historique (modal) compact */}
      {showHistory && selectedTenantId && (
        <div className="fixed inset-0 z-50 flex items-start justify-center p-4">
          <div className="absolute inset-0 bg-black/30" onClick={()=>setShowHistory(false)} />
          <div className="relative w-full max-w-2xl rounded-2xl bg-white shadow-lg border p-4 max-h-[85vh] overflow-auto">
            <div className="flex items-center justify-between mb-3">
              <div className="text-lg font-semibold">
                {tenants.find(t=>t.id===selectedTenantId)?.name} — Historique
              </div>
              <button onClick={()=>setShowHistory(false)} className="rounded border px-2 py-1 text-sm hover:bg-gray-50">Fermer</button>
            </div>

            {(invByTenant.get(selectedTenantId)||[]).slice().reverse().map(i=>{
              const paid = (i.status||"")==="Payé" || !!i.paid_at;
              const partial = (i.status||"")==="Partiel";
              return (
                <div key={i.id} className="border rounded mb-2">
                  <div className="px-3 py-2 flex items-center justify-between">
                    <div className="font-medium">INV-{i.id}</div>
                    <div className="text-xs text-gray-600">{i.currency}</div>
                  </div>
                  <div className="px-3 pb-3 text-sm">
                    {i.currency==="EUR" ? fmtEUR(i.expected_eur_cents) : fmtUSDC(i.amount_usdc_micro)}
                    {" · "}
                    {paid ? <span className="text-green-700">Payé</span> : partial ? <span className="text-amber-700">Partiel</span> : <span className="text-red-700">En attente</span>}
                    {i.paid_via_cash ? <span> · <b>cash</b></span> : null}
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Modale mot de passe sensible */}
      {showPwdModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
          <div className="absolute inset-0 bg-black/40" onClick={()=>setShowPwdModal(false)} />
          <form onSubmit={submitSensitivePassword} className="relative w-full max-w-sm rounded-2xl bg-white shadow-xl border p-4">
            <div className="text-base font-semibold mb-2">Action sensible</div>
            <div className="text-sm text-gray-600 mb-3">
              Saisissez le <b>mot de passe sensible</b> pour confirmer.
            </div>
            <input
              type="password"
              value={pwd}
              onChange={(e)=>setPwd(e.target.value)}
              placeholder="Mot de passe sensible"
              className="w-full rounded border px-3 py-2 mb-3"
              autoFocus
              required
            />
            <div className="flex items-center justify-end gap-2">
              <button type="button" onClick={()=>setShowPwdModal(false)} className="rounded border px-3 py-2 hover:bg-gray-50">
                Annuler
              </button>
              <button className="rounded bg-black text-white px-3 py-2 hover:bg-gray-900">
                Valider
              </button>
            </div>
          </form>
        </div>
      )}
    </div>
  );
}
