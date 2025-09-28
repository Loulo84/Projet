// C:\Projet\web\src\ui\Toast.jsx
import React, { createContext, useContext, useState } from "react";

const ToastCtx = createContext(null);

export function ToastProvider({ children }) {
  const [items, setItems] = useState([]);

  const push = (type, msg) => {
    const id = Math.random().toString(36).slice(2);
    setItems((l) => [...l, { id, type, msg }]);
    setTimeout(() => setItems((l) => l.filter((x) => x.id !== id)), 3000);
  };

  const api = {
    success: (m) => push("success", m),
    error: (m) => push("error", m),
    info: (m) => push("info", m),
  };

  return (
    <ToastCtx.Provider value={api}>
      {children}
      <div className="fixed z-50 top-3 right-3 space-y-2">
        {items.map((t) => (
          <div
            key={t.id}
            className={`rounded px-3 py-2 text-white shadow ${
              t.type === "success" ? "bg-green-600" : t.type === "error" ? "bg-red-600" : "bg-gray-800"
            }`}
          >
            {t.msg}
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

export const useToast = () => useContext(ToastCtx);
