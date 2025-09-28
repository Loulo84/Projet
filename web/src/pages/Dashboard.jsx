// src/pages/Dashboard.jsx
import React, { useEffect, useMemo, useState } from "react";
import { api } from "@/api";
import { bus, connectSSE } from "@/lib/bus";
import { Link } from "react-router-dom";
import { RefreshCcw, ArrowLeft, CheckCircle2, XCircle, Clock } from "lucide-react";

function Badge({ status }) {
  const map = {
    "Payé":   "bg-green-100 text-green-800",
    "Échec":  "bg-red-100 text-red-800",
    "En attente": "bg-yellow-100 text-yellow-800",
    default:  "bg-gray-100 text-gray-800",
  };
  const cls = map[status] || map.default;
  return <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium ${cls}`}>
    {status === "Payé" && <CheckCircle2 className="w-3 h-3" />}
    {status === "Échec" && <XCircle className="w-3 h-3" />}
    {status === "En attente" && <Clock className="w-3 h-3" />}
    {status}
  </span>;
}

export default function Dashboard() {
  const [loading, setLoading] = useState(true);
  const [rows, setRows] = useState([]);
  const [q, setQ] = useState("");
  const [showArchived, setShowArchived] = useState(false);

  async function load() {
    setLoading(true);
    try {
      const data = await api.dashboard(showArchived);
      setRows(data || []);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, [showArchived]);

  useEffect(() => {
    connectSSE();
    const refresh = () => load();
    bus.addEventListener("data-changed", refresh);
    bus.addEventListener("payment:ok", refresh);
    bus.addEventListener("payment:failed", refresh);
    return () => {
      bus.removeEventListener("data-changed", refresh);
      bus.removeEventListener("payment:ok", refresh);
      bus.removeEventListener("payment:failed", refresh);
    };
  }, []);

  const filtered = useMemo(() => {
    const s = q.trim().toLowerCase();
    if (!s) return rows;
    return rows.filter(r =>
      String(r.tenant_name || "").toLowerCase().includes(s) ||
      String(r.id).includes(s)
    );
  }, [rows, q]);

  const stats = useMemo(() => {
    const all = rows.length;
    const paid = rows.filter(r => r.status === "Payé").length;
    const fail = rows.filter(r => r.status === "Échec").length;
    const wait = rows.filter(r => r.status === "En attente").length;
    return { all, paid, fail, wait };
  }, [rows]);

  if (loading) return <div className="p-4">Chargement…</div>;

  return (
    <div className="space-y-6">
      {/* Titre + actions */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Link to="/" className="inline-flex items-center gap-1 text-sm px-3 py-1.5 border rounded hover:bg-gray-50">
            <ArrowLeft className="w-4 h-4" /> Accueil
          </Link>
          <h1 className="text-2xl font-bold">Dashboard (live)</h1>
        </div>
        <div className="flex items-center gap-2">
          <label className="text-sm inline-flex items-center gap-2">
            <input
              type="checkbox"
              checked={showArchived}
              onChange={e => setShowArchived(e.target.checked)}
            />
            Afficher archivés
          </label>
          <button onClick={load} className="inline-flex items-center gap-1 rounded border px-3 py-1.5 hover:bg-gray-50">
            <RefreshCcw className="w-4 h-4" /> Rafraîchir
          </button>
        </div>
      </div>

      {/* Cartes stats */}
      <div className="grid sm:grid-cols-4 gap-4">
        <CardStat title="Total" value={stats.all} />
        <CardStat title="Payé" value={stats.paid} tone="green" />
        <CardStat title="Échec" value={stats.fail} tone="red" />
        <CardStat title="En attente" value={stats.wait} tone="yellow" />
      </div>

      {/* Filtre + table */}
      <div className="flex items-center justify-between">
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Rechercher (locataire, #facture)…"
          className="rounded border px-3 py-2 w-full max-w-md"
        />
      </div>

      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="bg-gray-50">
            <tr>
              <th className="p-2 text-left">#</th>
              <th className="p-2 text-left">Locataire</th>
              <th className="p-2 text-left">Devise</th>
              <th className="p-2 text-left">Montant</th>
              <th className="p-2 text-left">Statut</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(r => (
              <tr key={r.id} className="border-t">
                <td className="p-2">INV-{r.id}</td>
                <td className="p-2">{r.tenant_name || "—"}</td>
                <td className="p-2">{r.currency}</td>
                <td className="p-2">
                  {r.currency === "EUR"
                    ? `${(r.expected_eur_cents / 100).toFixed(2)} €`
                    : `${(r.amount_usdc_micro / 1_000_000).toFixed(2)} USDC`}
                </td>
                <td className="p-2"><Badge status={r.status} /></td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr><td colSpan={5} className="p-3 text-gray-500">Aucune facture.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function CardStat({ title, value, tone = "gray" }) {
  const ring = {
    gray: "ring-gray-200",
    green: "ring-green-200",
    red: "ring-red-200",
    yellow: "ring-yellow-200",
  }[tone] || "ring-gray-200";
  return (
    <div className={`rounded-xl border p-4 ring-1 ${ring}`}>
      <div className="text-sm text-gray-500">{title}</div>
      <div className="text-3xl font-bold mt-1">{value}</div>
    </div>
  );
}
