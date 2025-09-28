// C:\Projet\web\src\pages\Audit.jsx
import React, { useEffect, useState } from "react";
import { api } from "../api";
import { useToast } from "../ui/Toast";

export default function Audit() {
  const toast = useToast();
  const [rows, setRows] = useState([]);
  const [limit, setLimit] = useState(200);
  const [userId, setUserId] = useState("");

  async function load() {
    try {
      const list = await api.auditList(limit, userId ? Number(userId) : null);
      setRows(list);
    } catch (e) {
      toast?.error("Chargement audit impossible");
    }
  }

  useEffect(() => { load(); /* eslint-disable-next-line */ }, []);

  return (
    <div className="max-w-6xl mx-auto p-4">
      <h1 className="text-2xl font-bold">Journal d’audit</h1>

      <div className="mt-3 flex flex-wrap items-center gap-2">
        <input className="rounded border px-3 py-2 w-32" type="number" placeholder="Limit" value={limit} onChange={(e)=>setLimit(e.target.value)} />
        <input className="rounded border px-3 py-2 w-40" type="number" placeholder="User ID (optionnel)" value={userId} onChange={(e)=>setUserId(e.target.value)} />
        <button onClick={load} className="rounded border px-3 py-2 hover:bg-gray-50 dark:hover:bg-gray-800">Rafraîchir</button>
      </div>

      <div className="mt-4 overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="bg-gray-50 dark:bg-gray-800">
            <tr>
              <th className="text-left p-2">ID</th>
              <th className="text-left p-2">User</th>
              <th className="text-left p-2">Action</th>
              <th className="text-left p-2">IP</th>
              <th className="text-left p-2">UA</th>
              <th className="text-left p-2">Meta</th>
              <th className="text-left p-2">Date</th>
            </tr>
          </thead>
          <tbody>
            {rows.map(r => (
              <tr key={r.id} className="border-t dark:border-gray-700">
                <td className="p-2">{r.id}</td>
                <td className="p-2">{r.user_id ?? "—"}</td>
                <td className="p-2">{r.action}</td>
                <td className="p-2">{r.ip || "—"}</td>
                <td className="p-2 truncate max-w-[240px]" title={r.ua}>{r.ua}</td>
                <td className="p-2">{r.meta ? <code className="text-xs">{JSON.stringify(r.meta)}</code> : "—"}</td>
                <td className="p-2">{new Date(r.created_at).toLocaleString()}</td>
              </tr>
            ))}
            {rows.length === 0 && (
              <tr><td colSpan={7} className="p-3 text-sm text-gray-600 dark:text-gray-300">Aucune entrée.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
