import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import Login from "./pages/Login";
import Layout from "./components/Layout";
import Targets from "./pages/Targets";
import Scans from "./pages/Scans";
import Vulnerabilities from "./pages/Vulnerabilities";
import Billing from "./pages/Billing";
import Dashboard from "./pages/Dashboard";
import Register from "./pages/Register";
import ProtectedRoute from "./components/ProtectedRoute";





function BillingSuccess() {
  return (
    <div className="p-8 max-w-lg bg-[#fbfaf8] min-h-screen">
      <div className="bg-white border border-[#7a1730]/30 rounded-lg p-6 text-center shadow-[0_4px_20px_rgba(122,23,48,0.08)]">
        <div className="text-[#7a1730] text-3xl mb-3">✓</div>

        <h1 className="text-xl font-serif text-[#1a1a1a] mb-2">
          Paiement réussi
        </h1>

        <p className="text-sm text-zinc-500 mb-4">
          Ton abonnement a été activé. Ça peut prendre quelques secondes
          pour se refléter ci-dessous.
        </p>

        <a
          href="/billing"
          className="inline-block bg-[#7a1730] hover:bg-[#5c1122] text-white font-semibold text-sm rounded px-4 py-2 transition-colors"
        >
          Retour à la facturation
        </a>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/register" element={<Register />} />
    <Route element={<ProtectedRoute />}>
  <Route element={<Layout />}>
    <Route path="/dashboard" element={<Dashboard />} />
    <Route path="/targets" element={<Targets />} />
    <Route path="/scans" element={<Scans />} />
    <Route path="/vulnerabilities" element={<Vulnerabilities />} />
    <Route path="/billing" element={<Billing />} />
    <Route path="/billing/success" element={<BillingSuccess />} />
    <Route path="/billing/cancel" element={<Navigate to="/billing" replace />} />
  </Route>
</Route>
    

        <Route path="/" element={<Navigate to="/login" replace />} />
      </Routes>
    </BrowserRouter>
  );
}