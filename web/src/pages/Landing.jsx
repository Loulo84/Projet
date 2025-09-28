import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import ImageUploader from "@/ui/ImageUploader";
import { api } from "@/api";

export default function Landing() {
  const [items, setItems] = useState([]);
  const [uploading, setUploading] = useState(false);

  async function load() { setItems(await api.mediaList() || []); }
  useEffect(() => { load(); }, []);

  async function handleFiles(files) {
    setUploading(true);
    try { await api.mediaUpload(files); await load(); }
    finally { setUploading(false); }
  }
  async function remove(id) { await api.mediaDelete(id); await load(); }

  return (
    <div className="min-h-screen bg-gradient-to-b from-white to-gray-50">
      <header className="border-b bg-white">
        <div className="max-w-6xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="font-bold text-lg">🏢 RentChain</div>
          <nav className="flex items-center gap-2 text-sm">
            <Link to="/login" className="rounded border px-3 py-1.5 hover:bg-gray-50">Espace client</Link>
            <Link to="/signup" className="rounded border px-3 py-1.5 hover:bg-gray-50">Inscription</Link>
          </nav>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-4 py-8 space-y-8">
        <section className="text-center">
          <h1 className="text-3xl font-bold">Gestion locative + paiements crypto</h1>
          <p className="text-gray-600 mt-2">Démos, captures et visuels à mettre en avant ci-dessous.</p>
        </section>

        <section className="grid lg:grid-cols-[1fr,1.2fr] gap-6 items-start">
          <div className="space-y-3">
            <div className="font-semibold">Ajouter des images</div>
            <ImageUploader onFiles={handleFiles} />
            {uploading && <div className="text-sm text-emerald-700">Téléversement en cours…</div>}
            <div className="text-xs text-gray-600">Formats image (png, jpg, webp, gif). Maximum 12 fichiers par envoi.</div>
          </div>

          <div className="rounded-xl border bg-white p-3">
            <div className="font-semibold mb-2">Galerie</div>
            {items.length === 0 ? (
              <div className="text-sm text-gray-500">Aucune image pour le moment.</div>
            ) : (
              <div className="grid sm:grid-cols-2 md:grid-cols-3 gap-3">
                {items.map(img => (
                  <figure key={img.id} className="rounded-lg border overflow-hidden">
                    <img src={img.url} alt={img.label || "image"} className="w-full h-40 object-cover" />
                    <figcaption className="flex items-center justify-between px-2 py-1 text-xs">
                      <span className="truncate">{img.label || img.filename || `#${img.id}`}</span>
                      <button onClick={()=>remove(img.id)} className="text-red-600 hover:underline">Supprimer</button>
                    </figcaption>
                  </figure>
                ))}
              </div>
            )}
          </div>
        </section>
      </main>
    </div>
  );
}
