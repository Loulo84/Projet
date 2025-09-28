import React, { useEffect, useMemo, useState } from "react";
import api from "@/api";

/**
 * RentDialog.jsx
 * Création de facture EUR (avec référence virement) ou USDC (crypto).
 * Props :
 *   open, onClose, tenants, onCreated
 */
export default function RentDialog({ open, onClose, tenants = [], onCreated }) {
  const [tenantId, setTenantId] = useState("");
  const [currency, setCurrency] = useState("EUR");
  const [amountEUR, setAmountEUR] = useState("");
  const [amountUSDC, setAmountUSDC] = useState("");
  const [dueDate, setDueDate] = useState("");
  const [loading, setLoading] = useState(false);
  const [createdInfo, setCreatedInfo] = useState(null);

  useEffect(() => {
    if (!open) {
      setTenantId("");
      setCurrency("EUR");
      setAmountEUR("");
      setAmountUSDC("");
      setDueDate("");
      setLoading(false);
      setCreatedInfo(null);
    }
  }, [open]);

  const canSubmit = useMemo(() => {
    if (!tenantId) return false;
    if (currency === "EUR") {
      const v = Number(String(amountEUR).replace(",", "."));
      return isFinite(v) && v > 0;
    } else {
      const v = Number(String(amountUSDC).replace(",", "."));
      return isFinite(v) && v > 0;
    }
  }, [tenantId, currency, amountEUR, amountUSDC]);

  const submit = async (e) => {
    e?.preventDefault?.();
    if (!canSubmit) return;
    try {
      setLoading(true);
      let res;
      if (currency === "EUR") {
        const euros = Number(String(amountEUR).replace(",", "."));
        const cents = Math.round(euros * 100);
        res = await api.addInvoiceEUR(Number(tenantId), cents, dueDate || null);
      } else {
        const usdc = Number(String(amountUSDC).replace(",", "."));
        const micro = Math.round(usdc * 1_000_000);
        res = await api.addInvoiceUSDC(Number(tenantId), micro, dueDate || null);
      }
      setCreatedInfo(res || null);
      if (typeof onCreated === "function") onCreated(res || null);
    } catch (err) {
      console.error(err);
      alert("Erreur lors de la création de la facture.");
    } finally {
      setLoading(false);
    }
  };

  if (!open) return null;

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 p-4">
      <div className="w-full max-w-lg rounded-2xl bg-white p-5 shadow-xl">
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold">Créer une facture</h2>
          <button
            onClick={onClose}
            className="rounded-md px-3 py-1 text-sm text-gray-500 hover:bg-gray-100"
          >
            Fermer
          </button>
        </div>

        <form onSubmit={submit} className="space-y-4">
          <div>
            <label className="mb-1 block text-sm font-medium">Locataire</label>
            <select
              className="w-full rounded-md border px-3 py-2"
              value={tenantId}
              onChange={(e) => setTenantId(e.target.value)}
              required
            >
              <option value="">— Sélectionner —</option>
              {tenants.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.name} {t.unit ? `— ${t.unit}` : ""}
                </option>
              ))}
            </select>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="mb-1 block text-sm font-medium">Devise</label>
              <select
                className="w-full rounded-md border px-3 py-2"
                value={currency}
                onChange={(e) => setCurrency(e.target.value)}
              >
                <option value="EUR">EUR (virement)</option>
                <option value="USDC">USDC (crypto)</option>
              </select>
            </div>
            <div>
              <label className="mb-1 block text-sm font-medium">Échéance</label>
              <input
                type="date"
                className="w-full rounded-md border px-3 py-2"
                value={dueDate}
                onChange={(e) => setDueDate(e.target.value)}
              />
            </div>
          </div>

          {currency === "EUR" ? (
            <div>
              <label className="mb-1 block text-sm font-medium">Montant (€)</label>
              <input
                type="number"
                step="0.01"
                min="0"
                placeholder="800.00"
                className="w-full rounded-md border px-3 py-2"
                value={amountEUR}
                onChange={(e) => setAmountEUR(e.target.value)}
                required
              />
              <p className="mt-1 text-xs text-gray-500">
                Une référence virement sera générée automatiquement.
              </p>
            </div>
          ) : (
            <div>
              <label className="mb-1 block text-sm font-medium">Montant (USDC)</label>
              <input
                type="number"
                step="0.000001"
                min="0"
                placeholder="800"
                className="w-full rounded-md border px-3 py-2"
                value={amountUSDC}
                onChange={(e) => setAmountUSDC(e.target.value)}
                required
              />
            </div>
          )}

          {createdInfo?.id && (
            <div className="rounded-md bg-green-50 p-3 text-sm text-green-700">
              Facture créée (ID: {createdInfo.id})
              {createdInfo.reference && (
                <>
                  <br />
                  Référence virement: <strong>{createdInfo.reference}</strong>
                </>
              )}
              <div className="mt-2">
                <a
                  href={api.receiptPdfUrl(createdInfo.id)}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-block rounded-md border px-3 py-1 text-xs hover:bg-gray-50"
                >
                  Télécharger le PDF
                </a>
              </div>
            </div>
          )}

          <div className="flex items-center justify-end gap-2">
            <button
              type="button"
              onClick={onClose}
              className="rounded-md px-3 py-2 text-sm text-gray-600 hover:bg-gray-100"
            >
              Annuler
            </button>
            <button
              type="submit"
              disabled={!canSubmit || loading}
              className="rounded-md bg-blue-600 px-4 py-2 text-sm font-medium text-white disabled:opacity-60"
            >
              {loading ? "Création..." : "Créer"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
