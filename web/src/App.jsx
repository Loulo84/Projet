// src/App.jsx
import React, { useEffect, useState } from "react";
import { Link, NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { api } from "@/api";
import { connectSSE, disconnectSSE } from "@/lib/bus";

function NavItem({ to, children }) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) =>
        `rounded px-3 py-1.5 border text-sm ${
          isActive ? "bg-gray-900 text-white border-gray-900" : "hover:bg-gray-50 border-gray-200"
        }`
      }
    >
      {children}
    </NavLink>
  );
}

export default function AppShell() {
  const loc = useLocation();
  const nav = useNavigate();
  const [menuOpen, setMenuOpen] = useState(false);

  // SSE partout sauf Landing/Auth
  useEffect(() => {
    const p = loc.pathname;
    const block = p === "/" || p.startsWith("/login") || p.startsWith("/signup");
    if (!block) connectSSE();
    else disconnectSSE();
  }, [loc.pathname]);

  async function handleLogout() {
    try {
      await api.logout();
    } catch {}
    nav("/login");
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="border-b bg-white">
        <div className="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Link to="/" className="font-bold text-lg">🏢 RentChain</Link>

            {/* Desktop nav */}
            <nav className="hidden md:flex items-center gap-2">
              <NavItem to="/app">Dashboard</NavItem>
              <NavItem to="/data">Données</NavItem>
              <NavItem to="/tenants">Locataires</NavItem>
              <NavItem to="/validation">À valider</NavItem>
              <NavItem to="/payments">Paiements</NavItem>
            </nav>
          </div>

          <nav className="hidden md:flex items-center gap-2">
            <NavItem to="/account">Compte</NavItem>
            <button onClick={handleLogout} className="rounded px-3 py-1.5 border hover:bg-gray-50 text-sm">
              Se déconnecter
            </button>
          </nav>

          {/* Mobile burger */}
          <button
            className="md:hidden rounded border px-3 py-1.5"
            onClick={() => setMenuOpen((v) => !v)}
            aria-label="Menu"
          >
            ☰
          </button>
        </div>

        {/* Mobile drawer */}
        {menuOpen && (
          <div className="md:hidden border-t bg-white">
            <div className="max-w-7xl mx-auto px-4 py-2 grid gap-2">
              <NavItem to="/app">Dashboard</NavItem>
              <NavItem to="/data">Données</NavItem>
              <NavItem to="/tenants">Locataires</NavItem>
              <NavItem to="/validation">À valider</NavItem>
              <NavItem to="/payments">Paiements</NavItem>
              <div className="h-px bg-gray-200 my-1" />
              <NavItem to="/account">Compte</NavItem>
              <button
                onClick={handleLogout}
                className="rounded px-3 py-1.5 border hover:bg-gray-50 text-left text-sm"
              >
                Se déconnecter
              </button>
            </div>
          </div>
        )}
      </header>

      <main className="max-w-7xl mx-auto p-4">
        <Outlet />
      </main>
    </div>
  );
}
