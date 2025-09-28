import React, { useEffect, useState } from "react";
import { api } from "@/api";
import { useToast } from "@/ui/Toast";
import { RefreshCcw } from "lucide-react";
import { bus } from "@/lib/bus";

export default function ValidationPage(){
  const toast = useToast();
  const [loading, setLoading] = useState(true);
  const [eur, setEur] = useState([]);
  const [usdc, setUsdc] = useState([]);

  async function load(){
    setLoading(true);
    try{
      const inv = await api.listInvoices();
      setEur(inv.filter(i=>i.status==="En attente" && i.currency==="EUR"));
      setUsdc(inv.filter(i=>i.status==="En attente" && i.currency==="USDC"));
    } finally { setLoading(false); }
  }

  useEffect(()=>{ load(); }, []);
  useEffect(()=>{
    const handler = () => load();
    bus.addEventListener("data-changed", handler);
    return () => bus.removeEventListener("data-changed", handler);
  }, []);

  return (
    <div className="max-w-5xl mx-auto p-4 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">À valider</h1>
        <button onClick={load} className="rounded border px-3 py-1.5 text-sm hover:bg-gray-50">
          <RefreshCcw className="inline w-4 h-4 mr-1" /> Rafraîchir
        </button>
      </div>

      {loading && <div>Chargement…</div>}

      <section className="rounded border p-4">
        <div className="font-semibold mb-2">Factures EUR en attente</div>
        <table className="w-full text-sm">
          <thead className="bg-gray-50">
            <tr>
              <th className="text-left p-2">ID</th>
              <th className="text-left p-2">Locataire</th>
              <th className="text-left p-2">Montant</th>
              <th className="text-left p-2">Échéance</th>
            </tr>
          </thead>
          <tbody>
            {eur.map(i=>(
              <tr key={i.id} className="border-t">
                <td className="p-2">INV-{i.id}</td>
                <td className="p-2">{i.tenant_name || "-"}</td>
                <td className="p-2">{(i.expected_eur_cents/100).toFixed(2)} €</td>
                <td className="p-2">{i.due_date || "—"}</td>
              </tr>
            ))}
            {eur.length===0 && <tr><td colSpan={4} className="p-3 text-gray-500">Rien à valider.</td></tr>}
          </tbody>
        </table>
      </section>

      <section className="rounded border p-4">
        <div className="font-semibold mb-2">Factures USDC en attente</div>
        <table className="w-full text-sm">
          <thead className="bg-gray-50">
            <tr>
              <th className="text-left p-2">ID</th>
              <th className="text-left p-2">Locataire</th>
              <th className="text-left p-2">Montant</th>
              <th className="text-left p-2">Échéance</th>
            </tr>
          </thead>
        <tbody>
          {usdc.map(i=>(
            <tr key={i.id} className="border-t">
              <td className="p-2">INV-{i.id}</td>
              <td className="p-2">{i.tenant_name || "-"}</td>
              <td className="p-2">{(i.amount_usdc).toFixed(6)} USDC</td>
              <td className="p-2">{i.due_date || "—"}</td>
            </tr>
          ))}
          {usdc.length===0 && <tr><td colSpan={4} className="p-3 text-gray-500">Rien à valider.</td></tr>}
        </tbody>
        </table>
      </section>
    </div>
  );
}
