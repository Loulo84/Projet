// src/router/RouterError.jsx
import React from "react";
import { useRouteError, isRouteErrorResponse, Link } from "react-router-dom";

export default function RouterError() {
  const err = useRouteError();

  if (isRouteErrorResponse(err)) {
    // Erreurs "réponse" de React Router (404, 401, 500...)
    return (
      <div className="max-w-lg mx-auto p-6">
        <h1 className="text-2xl font-bold mb-2">Oups… {err.status} {err.statusText}</h1>
        <p className="text-gray-600 mb-4">{err.data || "Une erreur est survenue."}</p>
        <Link className="underline text-blue-700" to="/">Retour à l’accueil</Link>
      </div>
    );
  }

  // Erreurs JS génériques
  const message = (err && (err.message || String(err))) || "Erreur inconnue";
  return (
    <div className="max-w-lg mx-auto p-6">
      <h1 className="text-2xl font-bold mb-2">Oups… une erreur est survenue</h1>
      <pre className="text-sm bg-gray-100 p-3 rounded">{message}</pre>
      <div className="mt-4"><Link className="underline text-blue-700" to="/">Retour à l’accueil</Link></div>
    </div>
  );
}
