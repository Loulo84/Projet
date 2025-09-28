import * as AlertDialog from "@radix-ui/react-alert-dialog";
import React, { useState } from "react";

export default function DeleteDialog({ open, onOpenChange, onConfirm, title, description }) {
  const [pwd, setPwd] = useState("");
  const [loading, setLoading] = useState(false);

  async function handleConfirm() {
    setLoading(true);
    try { await onConfirm(pwd); } finally { setLoading(false); }
  }

  return (
    <AlertDialog.Root open={open} onOpenChange={onOpenChange}>
      <AlertDialog.Portal>
        <AlertDialog.Overlay className="fixed inset-0 bg-black/20" />
        <AlertDialog.Content className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-[92vw] max-w-md rounded-xl bg-white p-5 shadow">
          <AlertDialog.Title className="text-lg font-semibold">{title}</AlertDialog.Title>
          <AlertDialog.Description className="mt-2 text-sm text-gray-600">{description}</AlertDialog.Description>
          <div className="mt-4 space-y-2">
            <label className="text-sm">Mot de passe de suppression</label>
            <input
              type="password"
              value={pwd}
              onChange={(e) => setPwd(e.target.value)}
              className="w-full rounded border px-3 py-2"
              placeholder="••••••"
            />
          </div>
          <div className="mt-5 flex justify-end gap-2">
            <AlertDialog.Cancel asChild>
              <button className="rounded border px-3 py-2 hover:bg-gray-50">Annuler</button>
            </AlertDialog.Cancel>
            <AlertDialog.Action asChild>
              <button
                onClick={handleConfirm}
                disabled={loading || pwd.length < 1}
                className="rounded bg-red-600 text-white px-3 py-2 hover:bg-red-700 disabled:opacity-60"
              >
                {loading ? "Suppression…" : "Supprimer"}
              </button>
            </AlertDialog.Action>
          </div>
        </AlertDialog.Content>
      </AlertDialog.Portal>
    </AlertDialog.Root>
  );
}
