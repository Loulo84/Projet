// src/pages/DataPage.jsx
import React, { useEffect, useMemo, useState } from "react";
import { api } from "@/api";
import { Building2, User2, Plus, X, KeyRound, Check, RotateCcw, Archive } from "lucide-react";
import DeleteDialog from "@/ui/DeleteDialog";
import RentDialog from "@/ui/RentDialog";
import { useToast } from "@/ui/Toast";
import * as Dialog from "@radix-ui/react-dialog";
import { emitDataChanged } from "@/lib/bus";

async function withOrg(fn) {
  try { return await fn(); }
  catch (e) {
    if (e?.response?.status === 403) {
      try { await api.me(); } catch {}
      return await fn(); // retry une fois
    }
    throw e;
  }
}

export default function DataPage() {
  const toast = useToast();

  const [loading, setLoading] = useState(true);
  const [me, setMe] = useState(null);
  const [properties, setProps] = useState([]);
  const [tenants, setTenants] = useState([]);
  const [showArchived, setShowArchived] = useState(false);

  const [newProp, setNewProp] = useState("");
  const [tenantDraft, setTenantDraft] = useState({});

  const [deletePassNew, setDeletePassNew] = useState("");
  const [savingPass, setSavingPass] = useState(false);
  const [passSavedOk, setPassSavedOk] = useState(false);

  const [deleteTarget, setDeleteTarget] = useState(null);
  const [rentTarget, setRentTarget] = useState(null);
  const [pwdDialogOpen, setPwdDialogOpen] = useState(false);

  const load = async (_showArchived = showArchived) => {
    setLoading(true);
    try {
      const u = await api.me().catch(() => null);
      setMe(u);
      const [p, t] = await Promise.all([
        withOrg(() => api.listProperties(_showArchived)),
        withOrg(() => api.listTenants({ include_archived: _showArchived })),
      ]);
      setProps(p || []);
      setTenants(t || []);
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => { load(); /* eslint-disable-next-line */ }, []);

  const byProp = useMemo(() => {
    const map = new Map();
    for (const p of properties) map.set(p.id, []);
    for (const t of tenants) if (map.has(t.property_id)) map.get(t.property_id).push(t);
    return map;
  }, [properties, tenants]);

  const addProperty = async () => {
    const name = newProp.trim();
    if (!name) { toast?.info("Nom d’immeuble requis."); return; }
    try {
      await withOrg(() => api.addProperty(name));
      setNewProp("");
      await load();
      toast?.success("Immeuble ajouté.");
      emitDataChanged({ what: "property:add" });
    } catch (e) {
      const msg = e?.response?.data?.error || e?.message || "Échec de l’ajout d’immeuble";
      toast?.error(msg);
    }
  };

  const addTenant = async (property_id) => {
    const d = tenantDraft[property_id] || {};
    const name = (d.name || "").trim();
    const unit = (d.unit || "").trim();
    if (!name) return toast?.info("Nom du locataire requis.");
    try {
      await withOrg(() => api.addTenant(property_id, name, unit));
      setTenantDraft((prev) => ({ ...prev, [property_id]: { name: "", unit: "" } }));
      await load();
      toast?.success("Locataire ajouté.");
      emitDataChanged({ what: "tenant:add" });
    } catch (e) {
      toast?.error(e?.response?.data?.error || "Échec de l’ajout du locataire");
    }
  };

  const askDeleteProperty = (id, name) => setDeleteTarget({ type: "property", id, name });
  const askDeleteTenant   = (id, name) => setDeleteTarget({ type: "tenant", id, name });

  async function confirmDelete(pwd) {
    try {
      if (deleteTarget.type === "property") await withOrg(() => api.deleteProperty(deleteTarget.id, pwd));
      else await withOrg(() => api.deleteTenant(deleteTarget.id, pwd));
      setDeleteTarget(null);
      await load();
      toast?.success("Archivé. Historique conservé.");
      emitDataChanged({ what: "archive" });
    } catch (e) {
      toast?.error(e?.response?.data?.error || "Mot de passe invalide");
    }
  }

  const toggleArchived = async () => {
    const val = !showArchived; setShowArchived(val); await load(val);
  };

  const saveDeletePassword = async () => {
    if (!deletePassNew || deletePassNew.length < 6) {
      toast?.error("Mot de passe : minimum 6 caractères."); return;
    }
    setSavingPass(true); setPassSavedOk(false);
    try {
      await api.setDeletePassword(deletePassNew);
      setDeletePassNew(""); setPassSavedOk(true);
      setTimeout(() => setPassSavedOk(false), 1500);
      toast?.success("Mot de passe enregistré."); setPwdDialogOpen(false);
    } catch (e) {
      toast?.error(e?.response?.data?.error || "Erreur d’enregistrement");
    } finally { setSavingPass(false); }
  };

  async function restoreProperty(id) {
    try { await withOrg(() => api.restoreProperty(id)); await load(); }
    catch (e) { toast?.error(e?.response?.data?.error || "Échec restauration"); }
  }

  function openRent(tenant) { setRentTarget({ tenantId: tenant.id, name: tenant.name }); }

  async function submitRent({ tenantId, currency, amount, due }) {
    const v = Number(String(amount).replace(",", "."));
    if (!isFinite(v) || v <= 0) return toast?.error("Montant invalide.");
    try {
      if (currency === "EUR") await withOrg(() => api.addInvoiceEUR(tenantId, Math.round(v * 100), due || undefined));
      else await withOrg(() => api.addInvoiceUSDC(tenantId, Math.round(v * 1_000_000), due || undefined));
      setRentTarget(null); toast?.success("Loyer créé."); emitDataChanged({ what: "invoice:add" });
    } catch (e) {
      toast?.error(e?.response?.data?.error || "Erreur lors de la création");
    }
  }

  const quotaMax = me?.quotas?.properties ?? 0;
  const activeProps = properties.filter(p => !p.deleted_at).length;
  const quotaReached = !showArchived && quotaMax > 0 && activeProps >= quotaMax;

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold">📑 Données</h2>
        <div className="flex items-center gap-3">
          <label className="text-sm inline-flex items-center gap-2 cursor-pointer select-none">
            <input type="checkbox" checked={showArchived} onChange={toggleArchived} />
            <span>Afficher archivés</span>
          </label>

          <Dialog.Root open={pwdDialogOpen} onOpenChange={setPwdDialogOpen}>
            <Dialog.Trigger asChild>
              <button className="inline-flex items-center gap-2 rounded border px-3 py-1.5 text-sm hover:bg-gray-50">
                <KeyRound className="w-4 h-4" />
                <span className="hidden sm:inline">Mot de passe suppression</span>
              </button>
            </Dialog.Trigger>
            <Dialog.Portal>
              <Dialog.Overlay className="fixed inset-0 bg-black/20" />
              <Dialog.Content className="fixed right-4 top-4 w-[92vw] max-w-md rounded-xl bg-white p-5 shadow-lg">
                <Dialog.Title className="text-base font-semibold flex items-center gap-2">
                  <KeyRound className="w-4 h-4" /> Mot de passe de suppression
                </Dialog.Title>
                <div className="mt-4 flex gap-2">
                  <input
                    type="password"
                    className="flex-1 rounded border px-3 py-2"
                    placeholder="Nouveau mot de passe (≥ 6 chars)"
                    value={deletePassNew}
                    onChange={(e) => setDeletePassNew(e.target.value)}
                  />
                  <button
                    onClick={saveDeletePassword}
                    disabled={savingPass}
                    className="inline-flex items-center gap-2 rounded bg-gray-800 text-white px-3 py-2 hover:bg-black disabled:opacity-60"
                  >
                    {savingPass ? "Enregistrement…" : "Définir"}
                  </button>
                </div>
                {passSavedOk && (
                  <div className="mt-2 inline-flex items-center gap-1 text-green-700 text-sm">
                    <Check className="w-4 h-4" /> Enregistré
                  </div>
                )}
                <div className="mt-4 flex justify-end">
                  <Dialog.Close asChild>
                    <button className="rounded border px-3 py-2 hover:bg-gray-50">Fermer</button>
                  </Dialog.Close>
                </div>
              </Dialog.Content>
            </Dialog.Portal>
          </Dialog.Root>
        </div>
      </div>

      <div className="flex gap-2">
        <input
          className="flex-1 rounded border px-3 py-2"
          placeholder="Nom immeuble"
          value={newProp}
          onChange={(e) => setNewProp(e.target.value)}
        />
        <button
          onClick={addProperty}
          disabled={quotaReached}
          className="inline-flex items-center gap-2 rounded bg-blue-600 text-white px-3 py-2 hover:bg-blue-700 disabled:opacity-60"
        >
          <Plus size={16} /> Ajouter immeuble
        </button>
      </div>
      {quotaReached && (
        <div className="text-sm text-red-700 -mt-2">
          Quota d’immeubles atteint ({activeProps}/{quotaMax}). Archive un immeuble ou passe en PRO.
        </div>
      )}

      {loading && <div className="text-sm opacity-70">Chargement…</div>}

      <div className="space-y-6">
        {properties.map((p) => {
          const list = byProp.get(p.id) || [];
          const draft = tenantDraft[p.id] || { name: "", unit: "" };
          return (
            <div key={p.id} className="rounded border bg-white">
              <div className="group flex items-center justify-between px-4 py-3 border-b">
                <div className="flex items-center gap-2">
                  <Building2 className="w-5 h-5 text-blue-600" />
                  <div className="font-semibold">{p.name}</div>
                  {p.deleted_at && <span className="text-xs ml-2 rounded bg-gray-200 px-2 py-0.5">archivé</span>}
                </div>
                <div className="flex items-center gap-2">
                  {p.deleted_at ? (
                    <button onClick={() => restoreProperty(p.id)} className="rounded p-1 hover:bg-gray-50" title="Restaurer">
                      <RotateCcw className="w-4 h-4" />
                    </button>
                  ) : (
                    <button onClick={() => setDeleteTarget({ type: "property", id: p.id, name: p.name })}
                            className="rounded p-1 hover:bg-red-50 hover:text-red-600" title="Archiver">
                      <Archive className="w-4 h-4" />
                    </button>
                  )}
                </div>
              </div>

              <div className="p-4 space-y-3">
                {list.map((t) => (
                  <div key={t.id} className="rounded border">
                    <div className="group flex items-center justify-between px-3 py-2">
                      <div className="flex items-center gap-2">
                        <User2 className="w-4 h-4" />
                        <span className="font-medium">{t.name}</span>
                        {t.unit && <span className="opacity-70">— {t.unit}</span>}
                        {t.deleted_at && <span className="text-xs ml-2 rounded bg-gray-200 px-2 py-0.5">archivé</span>}
                      </div>
                      {!t.deleted_at && (
                        <button
                          onClick={() => setDeleteTarget({ type: "tenant", id: t.id, name: t.name })}
                          className="opacity-0 group-hover:opacity-100 transition-opacity rounded p-1 hover:bg-red-50 hover:text-red-600"
                          title="Archiver le locataire"
                        >
                          <X className="w-4 h-4" />
                        </button>
                      )}
                    </div>

                    <div className="px-3 pb-3">
                      <button onClick={() => openRent(t)} className="rounded border px-3 py-1 hover:bg-gray-50">
                        Créer loyer
                      </button>
                    </div>
                  </div>
                ))}

                {!p.deleted_at && (
                  <div className="rounded border p-3 bg-gray-50">
                    <div className="grid sm:grid-cols-[1fr,160px,140px] gap-2">
                      <input
                        className="rounded border px-2 py-2"
                        placeholder="Nom du locataire"
                        value={draft.name}
                        onChange={(e) => setTenantDraft((s) => ({ ...s, [p.id]: { ...(s[p.id]||{}), name: e.target.value } }))}
                      />
                      <input
                        className="rounded border px-2 py-2"
                        placeholder="Appartement"
                        value={draft.unit}
                        onChange={(e) => setTenantDraft((s) => ({ ...s, [p.id]: { ...(s[p.id]||{}), unit: e.target.value } }))}
                      />
                      <button onClick={() => addTenant(p.id)} className="rounded bg-gray-900 text-white px-3 py-2 hover:bg-black">
                        <Plus className="inline w-4 h-4 mr-1" /> Ajouter locataire
                      </button>
                    </div>
                  </div>
                )}
              </div>
            </div>
          );
        })}
        {properties.length === 0 && !loading && (
          <div className="text-gray-600">Aucun immeuble. Crée le premier ci-dessus.</div>
        )}
      </div>

      <DeleteDialog
        open={!!deleteTarget}
        onOpenChange={(v) => !v && setDeleteTarget(null)}
        onConfirm={confirmDelete}
        title={deleteTarget?.type === "property" ? "Archiver l’immeuble" : "Archiver le locataire"}
        description={deleteTarget?.name ? `Cible : ${deleteTarget.name}` : ""}
      />

      <RentDialog
        open={!!rentTarget}
        onOpenChange={(v)=>!v && setRentTarget(null)}
        onSubmit={submitRent}
        defaultTenantId={rentTarget?.tenantId}
        tenantName={rentTarget?.name}
      />
    </div>
  );
}
