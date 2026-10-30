/**
 * Register Page
 *
 * Calls POST /api/auth/register, which creates a new Organization and
 * an admin User in one shot (see auth.py). On success, logs the user
 * in immediately using the same flow as Login.jsx -- the backend does
 * NOT return tokens on register, so we chain a login call right after
 * (see handleSubmit).
 *
 * Password rules are shown up front (8+ chars, 1 uppercase, 1 digit)
 * to match validate_password() server-side, so the user isn't
 * surprised by a 400 after submitting.
 */

import { useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import apiClient from "../api/client";
import { useAuth } from "../Authcontext";

export default function Register() {
  const navigate = useNavigate();
  const { login } = useAuth();
  const [username, setUsername] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [orgName, setOrgName] = useState("");
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      await apiClient.post("/api/auth/register", {
        username,
        email,
        password,
        organization_name: orgName.trim() || undefined,
      });

      // Register doesn't set auth cookies itself, so log in right after
      // with the same credentials -- the backend sets the httpOnly
      // cookies on this /login response, then we ask AuthContext to
      // re-check /api/auth/me.
      await apiClient.post("/api/auth/login", {
        identifier: email,
        password,
      });

      await login();
      navigate("/dashboard");
    } catch (err) {
      const message =
        err.response?.data?.message ||
        "Une erreur est survenue lors de l'inscription.";
      setError(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-[#fbfaf8] px-4">
      <div className="w-full max-w-sm">
        <div className="text-center mb-8">
          <div className="inline-block px-3 py-1 rounded-full bg-[#0d0607] border border-[#3d0c17] text-[#c94f6c] text-xs tracking-widest uppercase mb-4">
            Bug Bounty Platform
          </div>
          <h1 className="text-2xl font-serif text-[#1a1a1a]">Créer un compte</h1>
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
              Nom d'utilisateur
            </label>
            <input
              type="text"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              required
              className="w-full bg-white border border-zinc-300 rounded px-3 py-2 text-[#1a1a1a] text-sm focus:outline-none focus:border-[#7a1730] focus:ring-1 focus:ring-[#7a1730]/30"
              placeholder="alice"
            />
          </div>

          <div>
            <label className="block text-xs uppercase tracking-wide text-zinc-500 mb-1">
              Email
            </label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
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
              minLength={8}
              className="w-full bg-white border border-zinc-300 rounded px-3 py-2 text-[#1a1a1a] text-sm focus:outline-none focus:border-[#7a1730] focus:ring-1 focus:ring-[#7a1730]/30"
              placeholder="••••••••"
            />
            <p className="text-xs text-zinc-400 mt-1">
              8 caractères min., avec au moins 1 majuscule et 1 chiffre.
            </p>
          </div>

          <div>
            <label className="block text-xs uppercase tracking-wide text-zinc-500 mb-1">
              Nom de l'organisation <span className="text-zinc-400 normal-case">(optionnel)</span>
            </label>
            <input
              type="text"
              value={orgName}
              onChange={(e) => setOrgName(e.target.value)}
              className="w-full bg-white border border-zinc-300 rounded px-3 py-2 text-[#1a1a1a] text-sm focus:outline-none focus:border-[#7a1730] focus:ring-1 focus:ring-[#7a1730]/30"
              placeholder="Acme Corp"
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            className="w-full bg-[#7a1730] hover:bg-[#5c1122] disabled:opacity-50 disabled:cursor-not-allowed text-white font-semibold text-sm rounded px-3 py-2 transition-colors"
          >
            {loading ? "Création..." : "Créer mon compte"}
          </button>
        </form>

        <p className="text-center text-sm text-zinc-500 mt-4">
          Déjà un compte ?{" "}
          <Link to="/login" className="text-[#7a1730] font-medium hover:underline">
            Se connecter
          </Link>
        </p>
      </div>
    </div>
  );
}