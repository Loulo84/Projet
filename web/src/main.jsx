// src/main.jsx
import React from "react";
import ReactDOM from "react-dom/client";
import { createBrowserRouter, RouterProvider } from "react-router-dom";
import "@/index.css";

import AppShell from "@/App";
import Landing from "@/pages/Landing.jsx";
import Auth from "@/pages/Auth.jsx";
import Dashboard from "@/pages/Dashboard.jsx";
import DataPage from "@/pages/DataPage.jsx";
import TenantsPage from "@/pages/TenantsPage.jsx";
import ValidationPage from "@/pages/ValidationPage.jsx";
import PaymentsPage from "@/pages/PaymentsPage.jsx";
import Account from "@/pages/Account.jsx";
import Organization from "@/pages/Organization.jsx";
import Audit from "@/pages/Audit.jsx";
import Security from "@/pages/Security.jsx";
import NotFound from "@/pages/NotFound.jsx";

import Protected from "@/lib/protect.jsx";
import RouterError from "@/router/RouterError.jsx";
import ErrorBoundary from "@/components/ErrorBoundary.jsx";
import { ToastProvider } from "@/ui/Toast.jsx";

const router = createBrowserRouter(
  [
    { path: "/", element: <Landing />, errorElement: <RouterError /> },
    { path: "/login", element: <Auth mode="login" />, errorElement: <RouterError /> },
    { path: "/signup", element: <Auth mode="signup" />, errorElement: <RouterError /> },

    {
      path: "/",
      element: (
        <Protected>
          <AppShell />
        </Protected>
      ),
      errorElement: <RouterError />,
      children: [
        { path: "app", element: <Dashboard /> },
        { path: "data", element: <DataPage /> },
        { path: "tenants", element: <TenantsPage /> },
        { path: "validation", element: <ValidationPage /> },
        { path: "payments", element: <PaymentsPage /> },
        { path: "account", element: <Account /> },
        { path: "organization", element: <Organization /> },
        { path: "audit", element: <Audit /> },
        { path: "security", element: <Security /> },
      ],
    },

    { path: "*", element: <NotFound />, errorElement: <RouterError /> },
  ],
  { future: { v7_partialHydration: true } }
);

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <ToastProvider>
      <ErrorBoundary>
        <RouterProvider router={router} />
      </ErrorBoundary>
    </ToastProvider>
  </React.StrictMode>
);
