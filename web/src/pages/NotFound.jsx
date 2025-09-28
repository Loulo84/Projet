// src/pages/NotFound.jsx
import React from "react";
import { Link, useLocation } from "react-router-dom";

export default function NotFound() {
  const loc = useLocation();
  return (
    <div className="max-w-lg mx-auto p-6 text-center">
      <h1 className="text-2xl font-bold mb-2">Page introuvable (404)</h1>
      <div className="text-sm opacity-70 mb-4">L’URL demandée n’existe pas : <code>{loc.pathname}</code></div>
      <div className="space-x-4">
        <Link to="/" className="underline text-blue-700">Accueil</Link>
        <Link to="/app" className="underline text-blue-700">App</Link>
        <Link to="/login" className="underline text-blue-700">Connexion</Link>
      </div>
    </div>
  );
}
