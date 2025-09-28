// src/pages/Auth.jsx
import React, { useState } from "react";
import { useNavigate, useSearchParams, Link } from "react-router-dom";
import { api } from "@/api";
import { useToast } from "@/ui/Toast.jsx";

export default function Auth({ mode = "login" }) {
  const isLogin = mode === "login";
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [name, setName] = useState("");
  const [company, setCompany] = useState("");
  const [showPwd, setShowPwd] = useState(false);
  const [loading, setLoading] = useState(false);
  const [params] = useSearchParams();
  const nav = useNavigate();
  const toast = useToast();

  async function submit(e) {
    e.preventDefault();
    setLoading(true);
    try {
      if (isLogin) {
        await api.login({ email, password, remember: true });
        toast?.success("Bienvenue !");
      } else {
        await api.signup({ email, password, name, company, remember: true });
        toast?.success("Compte créé.");
      }
      const next = params.get("next");
      nav(next || "/app", { replace: true });
    } catch (err) {
      const msg = err?.response?.data?.error || "Erreur d’authentification";
      toast?.error(msg);
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen grid place-items-center bg-gray-50 p-4">
      <div className="w-full max-w-md rounded-2xl bg-white p-6 shadow">
        <h1 className="text-xl font-semibold mb-1">
          {isLogin ? "Connexion" : "Créer un compte"}
        </h1>
        <p className="text-sm text-gray-600 mb-4">
          {isLogin ? "Accédez à votre espace." : "Gestion locative simple — virements & USDC."}
        </p>

        <form onSubmit={submit} className="space-y-3">
          {!isLogin && (
            <>
              <div>
                <label className="text-sm">Nom</label>
                <input
                  className="mt-1 w-full rounded border px-3 py-2"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  autoComplete="name"
                />
              </div>
              <div>
                <label className="text-sm">Société (facultatif)</label>
                <input
                  className="mt-1 w-full rounded border px-3 py-2"
                  value={company}
                  onChange={(e) => setCompany(e.target.value)}
                  autoComplete="organization"
                />
              </div>
            </>
          )}

          <div>
            <label className="text-sm">Email</label>
            <input
              className="mt-1 w-full rounded border px-3 py-2"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              autoComplete="email"
              required
            />
          </div>

          <div>
            <label className="text-sm">Mot de passe</label>
            <div className="mt-1 flex">
              <input
                className="w-full rounded-l border px-3 py-2"
                type={showPwd ? "text" : "password"}
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete={isLogin ? "current-password" : "new-password"}
                required
              />
              <button
                type="button"
                onClick={() => setShowPwd((v) => !v)}
                className="rounded-r border border-l-0 px-3 py-2 text-sm hover:bg-gray-50"
              >
                {showPwd ? "Masquer" : "Afficher"}
              </button>
            </div>
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full rounded bg-gray-900 text-white py-2 hover:bg-black disabled:opacity-60"
          >
            {loading ? "Veuillez patienter…" : isLogin ? "Se connecter" : "Créer le compte"}
          </button>
        </form>

        <div className="mt-4 text-sm text-center">
          {isLogin ? (
            <>Pas de compte ? <Link to="/signup" className="underline">Inscription</Link></>
          ) : (
            <>Déjà inscrit ? <Link to="/login" className="underline">Connexion</Link></>
          )}
        </div>
      </div>
    </div>
  );
}
