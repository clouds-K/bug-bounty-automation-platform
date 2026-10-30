/**
 * Login Page
 *
 * On successful login, stores the JWT access token in localStorage and
 * redirects to the dashboard. apiClient (src/api/client.js) picks up
 * that token automatically for every subsequent request.
 *
 * NOTE ON localStorage vs cookies:
 *   localStorage is used here for simplicity, matching how the token
 *   was handled throughout backend testing ($token in PowerShell). It
 *   is vulnerable to XSS (any injected script can read it) -- fine for
 *   a dev/personal project, but for a real production SaaS handling
 *   real user accounts, an httpOnly cookie set by the backend would be
 *   the safer choice. Worth revisiting before a real public launch.
 */

import { useState } from "react";
import apiClient from "../api/client";
import { useNavigate, Link } from "react-router-dom";
import { useAuth } from "../Authcontext";

export default function Login() {
  const navigate = useNavigate();
  const { login } = useAuth();
  const [identifier, setIdentifier] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      await apiClient.post("/api/auth/login", { identifier, password });
      await login();
      navigate("/dashboard");
    } catch (err) {
      const message =
        err.response?.data?.message ||
        "Identifiants incorrects. Vérifiez votre email et mot de passe.";
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#fbfaf8] px-4">
      <div className="w-full max-w-sm">
        <div className="text-center mb-8">
          <div className="inline-block px-3 py-1 rounded-full bg-[#7a1730] border border-[#5c1122] text-[#fbfaf8] text-xs tracking-widest uppercase mb-4">
            Bug Bounty Platform
          </div>
          <h1 className="text-2xl font-serif text-[#1a1a1a]">Connexion</h1>
        </div>

        <form
          onSubmit={handleSubmit}
          className="bg-white border border-[#ecdfe2] rounded-lg p-6 space-y-4 shadow-[0_8px_30px_rgba(122,23,48,0.08)]"
        >
          {error && (
            <div className="bg-[#fdf0f2] border border-[#f0c3cc] text-[#7a1730] text-sm rounded px-3 py-2">
              {error}
            </div>
          )}

          <div>
            <label className="block text-xs uppercase tracking-wide text-zinc-500 mb-1">
              Email
            </label>
            <input
              type="text"
              value={identifier}
              onChange={(e) => setIdentifier(e.target.value)}
              required
              className="w-full bg-white border border-zinc-300 rounded px-3 py-2 text-[#1a1a1a] text-sm focus:outline-none focus:border-[#7a1730] focus:ring-1 focus:ring-[#7a1730]/30"
              placeholder="vous@exemple.com"
            />
          </div>

          <div>
            <label className="block text-xs uppercase tracking-wide text-zinc-500 mb-1">
              Mot de passe
            </label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              className="w-full bg-white border border-zinc-300 rounded px-3 py-2 text-[#1a1a1a] text-sm focus:outline-none focus:border-[#7a1730] focus:ring-1 focus:ring-[#7a1730]/30"
              placeholder="••••••••"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-[#7a1730] hover:bg-[#5c1122] disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold text-sm rounded px-3 py-2 transition-colors"
          >
            {loading ? "Connexion..." : "Se connecter"}
          </button>
        </form>
        <p className="text-center text-sm text-zinc-500 mt-4">
  Pas encore de compte ?{" "}
  <Link to="/register" className="text-[#7a1730] font-medium hover:underline">
    Créer un compte
  </Link>
</p>
      </div>
    </div>
  );
}