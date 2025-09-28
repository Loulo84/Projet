// C:\Projet\web\src\pages\Security.jsx
import React, { useEffect, useState } from "react";
import { api } from "../api";
import { useToast } from "../ui/Toast";

export default function Security() {
  const toast = useToast();
  const [me, setMe] = useState(null);
  const [year, setYear] = useState(new Date().getFullYear());

  useEffect(()=>{ api.me().then(setMe).catch(()=>{}); }, []);

  const download = (url) => { window.location.href = url; };

  const doDelete = async () => {
    if (!confirm("Confirmer la suppression/anonymisation de votre compte ?")) return;
    try {
      await api.rgpdDelete();
      toast?.success("Compte anonymisé — déconnexion");
      window.location.href = "/";
    } catch (e) {
      toast?.error(e?.response?.data?.error || "Action impossible");
    }
  };

  return (
    <div className="max-w-4xl mx-auto p-4 space-y-6">
      <h1 className="text-2xl font-bold">Sécurité & Exports</h1>

      <section className="rounded border bg-white p-4">
        <div className="font-semibold">Chiffrement at-rest</div>
        <div className="text-sm text-gray-600 mt-1">
          Statut: <strong>{me?.encryption === "on" ? "ACTIVÉ" : "DÉSACTIVÉ"}</strong> (serveur)
        </div>
        <div className="text-xs text-gray-500 mt-1">
          Activez en ajoutant <code className="px-1 py-0.5 bg-gray-100 rounded">FILE_ENCRYPTION_KEY</code> (clé 32 octets base64).
        </div>
      </section>

      <section className="rounded border bg-white p-4">
        <div className="font-semibold mb-2">RGPD</div>
        <div className="flex flex-wrap items-center gap-2">
          <button onClick={()=>download(api.rgpdExportUrl())} className="rounded border px-3 py-2 hover:bg-gray-50">
            Exporter mes données (JSON)
          </button>
          <button onClick={doDelete} className="rounded bg-red-600 text-white px-3 py-2 hover:bg-red-700">
            Supprimer / Anonymiser mon compte
          </button>
        </div>
      </section>

      <section className="rounded border bg-white p-4">
        <div className="font-semibold mb-2">Export fiscal (FEC France)</div>
        <div className="flex items-center gap-2">
          <input className="rounded border px-3 py-2 w-32" type="number" value={year} onChange={(e)=>setYear(e.target.value)} />
          <button onClick={()=>download(api.fecUrl(year))} className="rounded border px-3 py-2 hover:bg-gray-50">
            Télécharger FEC {year}
          </button>
        </div>
        <div className="text-xs text-gray-500 mt-2">Inclut les factures marquées “Payé”.</div>
      </section>

      <section className="rounded border bg-white p-4">
        <div className="font-semibold mb-2">Sauvegarde</div>
        <button onClick={()=>download(api.downloadBackupUrl())} className="rounded border px-3 py-2 hover:bg-gray-50">
          Télécharger sauvegarde JSON (organisation)
        </button>
      </section>
    </div>
  );
}
