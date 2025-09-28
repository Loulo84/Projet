// src/pages/TenantsPage.jsx
import React, { useEffect, useMemo, useState } from "react";
import { api } from "@/api";
import { useToast } from "@/ui/Toast";
import { User2, Paperclip } from "lucide-react";
import DeleteDialog from "@/ui/DeleteDialog";
import RentDialog from "@/ui/RentDialog";
import { emitDataChanged, bus } from "@/lib/bus";
import { compressImageFile } from "@/lib/image";

const ACCEPT = "image/png,image/jpeg,image/webp,image/gif,application/pdf";
const MAX_MB = 8;

async function withOrg(fn) {
  try { return await fn(); }
  catch (e) {
    if (e?.response?.status === 403) {
      try { await api.me(); } catch {}
      return await fn();
    }
    throw e;
  }
}

export default function TenantsPage() {
  const toast = useToast();

  const [showArchived, setShowArchived] = useState(false);
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);

  const [editing, setEditing] = useState(null);
  const [uploadLabel, setUploadLabel] = useState({});
  const [deleteTarget, setDeleteTarget] = useState(null);
  const [rentTarget, setRentTarget] = useState(null);

  async function load(_arch = showArchived) {
    setLoading(true);
    try {
      await api.me().catch(()=>{});
      const t = await withOrg(() => api.listTenants({ include_archived: _arch }));
      setRows(Array.isArray(t) ? t : []);
    } finally { setLoading(false); }
  }
  useEffect(() => { load(); }, []);
  useEffect(() => {
    const handler = () => load();
    bus.addEventListener("data-changed", handler);
    return () => bus.removeEventListener("data-changed", handler);
  }, []);

  const actives = useMemo(
    () => (showArchived ? rows : rows.filter((t) => !t.deleted_at)),
    [rows, showArchived]
  );

  const tooBig = (f) => f.size > MAX_MB * 1024 * 1024;
  const typeOk = (f) => ACCEPT.split(",").includes(f.type);

  const onLeaseUpload = async (tenantId, file) => {
    if (!file) return;
    if (!typeOk(file)) return toast?.error("Type non autorisé (PDF ou image)");
    if (tooBig(file)) return toast?.error(`Fichier > ${MAX_MB} Mo`);
    try {
      const toSend = file.type.startsWith("image/") ? await compressImageFile(file) : file;
      await withOrg(() => api.uploadTenantLease(tenantId, toSend));
      await load();
      toast?.success("Bail chargé");
    } catch { toast?.error("Échec upload bail"); }
  };

  const onAttachUpload = async (tenantId, file) => {
    if (!file) return;
    if (!typeOk(file)) return toast?.error("Type non autorisé (PDF ou image)");
    if (tooBig(file)) return toast?.error(`Fichier > ${MAX_MB} Mo`);
    try {
      const label = (uploadLabel[tenantId] || "").trim();
      const toSend = file.type.startsWith("image/") ? await compressImageFile(file) : file;
      await withOrg(() => api.uploadTenantFile(tenantId, toSend, label));
      setUploadLabel((s) => ({ ...s, [tenantId]: "" }));
      await load();
      toast?.success("Pièce jointe chargée");
    } catch { toast?.error("Échec upload pièce jointe"); }
  };

  const onAttachDelete = async (tenantId, fileId) => {
    try { await withOrg(() => api.deleteTenantFile(tenantId, fileId)); await load(); }
    catch { toast?.error("Échec suppression pièce"); }
  };

  const openEdit = (t) => setEditing({ id: t.id, name: t.name, unit: t.unit || "", address: t.address || "" });
  const cancelEdit = () => setEditing(null);
  const saveEdit = async () => {
    try {
      await withOrg(() => api.updateTenant(editing.id, { name: editing.name, unit: editing.unit, address: editing.address }));
      setEditing(null);
      await load();
      toast?.success("Enregistré");
      emitDataChanged({ what:"tenant:update" });
    } catch (e) {
      toast?.error(e?.response?.data?.error || "Erreur enregistrement");
    }
  };

  useEffect(() => {
    function onKey(e) {
      if (!editing) return;
      if (e.key === "Enter") { e.preventDefault(); saveEdit(); }
      if (e.key === "Escape") { e.preventDefault(); cancelEdit(); }
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [editing]);

  const askDeleteTenant = (id, name) => setDeleteTarget({ type: "tenant", id, name });
  async function confirmDelete(pwd) {
    try {
      await withOrg(() => api.deleteTenant(deleteTarget.id, pwd));
      setDeleteTarget(null);
      await load();
      toast?.success("Archivé. Historique conservé.");
      emitDataChanged({ what:"archive" });
    } catch (e) { toast?.error(e?.response?.data?.error || "Mot de passe invalide"); }
  }
  async function restore(id) { await withOrg(() => api.restoreTenant(id)); await load(); }

  function openRent(t) { setRentTarget({ tenantId: t.id, name: t.name }); }
  async function submitRent({ tenantId, currency, amount, due }) {
    const v = Number(String(amount).replace(",", "."));
    if (!isFinite(v) || v <= 0) return toast?.error("Montant invalide.");
    try {
      if (currency === "EUR") await withOrg(() => api.addInvoiceEUR(tenantId, Math.round(v * 100), due || undefined));
      else await withOrg(() => api.addInvoiceUSDC(tenantId, Math.round(v * 1_000_000), due || undefined));
      setRentTarget(null); toast?.success("Loyer créé."); emitDataChanged({ what: "invoice:add" });
    } catch (e) { toast?.error(e?.response?.data?.error || "Erreur lors de la création"); }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">👤 Locataires</h2>
        <label className="text-sm inline-flex items-center gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={showArchived}
            onChange={async () => { const v = !showArchived; setShowArchived(v); await load(v); }}
          />
          <span>Afficher archivés</span>
        </label>
      </div>

      <div className="rounded border bg-white">
        <table className="w-full text-sm">
          <thead className="bg-gray-50">
            <tr>
              <th className="text-left p-2">Locataire</th>
              <th className="text-left p-2">Adresse / Appartement</th>
              <th className="text-left p-2">Bail (PDF/Image ≤ 8 Mo)</th>
              <th className="text-left p-2">Pièces jointes (PDF/Image)</th>
              <th className="text-right p-2">Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading && <tr><td colSpan={5} className="p-3 text-gray-500">Chargement…</td></tr>}
            {!loading && actives.length === 0 && <tr><td colSpan={5} className="p-3 text-gray-500">Aucun locataire</td></tr>}
            {actives.map((t) => {
              const isEdit = editing?.id === t.id;
              return (
                <tr key={t.id} className="border-t align-top">
                  <td className="p-2">
                    <div className="flex items-center gap-2">
                      <User2 className="w-4 h-4" />
                      {isEdit ? (
                        <input className="rounded border px-2 py-1" value={editing.name} onChange={(e)=>setEditing((s)=>({ ...s, name:e.target.value }))} />
                      ) : (
                        <span className="font-medium">{t.name}</span>
                      )}
                      {t.deleted_at && <span className="text-xs px-2 py-0.5 rounded border">Archivé</span>}
                    </div>
                  </td>

                  <td className="p-2">
                    {isEdit ? (
                      <div className="flex flex-col gap-1">
                        <input className="rounded border px-2 py-1" placeholder="Appartement" value={editing.unit} onChange={(e)=>setEditing((s)=>({ ...s, unit:e.target.value }))} />
                        <input className="rounded border px-2 py-1" placeholder="Adresse" value={editing.address} onChange={(e)=>setEditing((s)=>({ ...s, address:e.target.value }))} />
                      </div>
                    ) : (
                      <div className="text-sm">
                        <div>{t.unit || "—"}</div>
                        <div className="text-gray-600">{t.address || "—"}</div>
                      </div>
                    )}
                  </td>

                  <td className="p-2">
                    <input type="file" accept={ACCEPT} onChange={(e)=>onLeaseUpload(t.id, e.target.files?.[0])} />
                    {t.lease_path && <div className="mt-1 text-xs opacity-60">Bail chargé</div>}
                  </td>

                    <td className="p-2">
                      <div className="flex items-center gap-2">
                        <input className="rounded border px-2 py-1 w-36" placeholder="Libellé"
                          value={uploadLabel[t.id] || ""} onChange={(e)=>setUploadLabel((s)=>({ ...s, [t.id]: e.target.value }))} />
                        <label className="rounded border px-2 py-1 cursor-pointer hover:bg-gray-50">
                          <Paperclip className="inline w-4 h-4 mr-1" /> Joindre
                          <input type="file" className="hidden" accept={ACCEPT}
                            onChange={(e)=>onAttachUpload(t.id, e.target.files?.[0])} />
                        </label>
                      </div>
                      {(t.files || []).length > 0 && (
                        <ul className="mt-2 space-y-1">
                          {t.files.map((f)=>(
                            <li key={f.id} className="text-xs flex items-center justify-between gap-2">
                              <a href={f.url} target="_blank" rel="noreferrer" className="underline">{f.label || f.filename}</a>
                              <button onClick={()=>onAttachDelete(t.id, f.id)} className="text-red-600 hover:underline">Supprimer</button>
                            </li>
                          ))}
                        </ul>
                      )}
                    </td>

                  <td className="p-2 text-right">
                    {isEdit ? (
                      <div className="inline-flex gap-2">
                        <button onClick={saveEdit} className="rounded border px-2 py-1 hover:bg-gray-50">Enregistrer</button>
                        <button onClick={cancelEdit} className="rounded border px-2 py-1 hover:bg-gray-50">Annuler</button>
                      </div>
                    ) : (
                      <div className="inline-flex gap-2">
                        {!t.deleted_at && <button onClick={()=>openEdit(t)} className="rounded border px-2 py-1 hover:bg-gray-50">Éditer</button>}
                        {!t.deleted_at && <button onClick={()=>openRent(t)} className="rounded border px-2 py-1 hover:bg-gray-50">Créer loyer</button>}
                        {t.deleted_at
                          ? <button onClick={()=>restore(t.id)} className="rounded border px-2 py-1 hover:bg-gray-50">Restaurer</button>
                          : <button onClick={()=>askDeleteTenant(t.id, t.name)} className="rounded border px-2 py-1 hover:bg-gray-50 text-red-700">Archiver</button>
                        }
                      </div>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <DeleteDialog
        open={!!deleteTarget}
        onOpenChange={(v)=>!v && setDeleteTarget(null)}
        title="Archiver le locataire"
        description={`Saisissez le mot de passe de suppression pour archiver « ${deleteTarget?.name ?? ""} ». (Historique conservé)`}
        onConfirm={confirmDelete}
      />
      <RentDialog
        open={!!rentTarget}
        onOpenChange={(v)=>!v && setRentTarget(null)}
        defaultTenantId={rentTarget?.tenantId}
        defaultTenantName={rentTarget?.name}
        onSubmit={submitRent}
      />
    </div>
  );
}
