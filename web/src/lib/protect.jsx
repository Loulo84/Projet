// src/lib/protect.jsx
import React, { useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { api } from "@/api";

export default function Protected({ children }) {
  const [state, setState] = useState("checking"); // checking | ok
  const navigate = useNavigate();
  const loc = useLocation();

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        await api.me();                // vérifie la session via cookie
        if (!alive) return;
        setState("ok");
      } catch {
        if (!alive) return;
        const next = encodeURIComponent(loc.pathname + loc.search);
        navigate(`/login?next=${next}`, { replace: true });
      }
    })();
    return () => { alive = false; };
  }, [navigate, loc.pathname, loc.search]);

  if (state !== "ok") {
    return (
      <div className="min-h-[40vh] flex items-center justify-center text-sm text-gray-600">
        Vérification de session…
      </div>
    );
  }
  return children;
}
