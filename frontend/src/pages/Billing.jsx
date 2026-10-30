/**
 * Billing Page
 *
 * Shows the organization's current plan and lets an admin upgrade via
 * Stripe Checkout. Mirrors the backend contract exactly:
 *   GET  /api/billing/subscription  -> current plan/status
 *   GET  /api/billing/plans         -> available plans to display
 *   POST /api/billing/checkout      -> { plan } -> { checkout_url }
 *
 * IMPORTANT: this page NEVER sets the plan directly. It only redirects
 * to Stripe's hosted checkout page (window.location.href = checkout_url).
 * The plan is activated exclusively by the backend's Stripe webhook once
 * payment is confirmed -- see app/routes/billing.py's
 * checkout.session.completed handler. This matches the security fix
 * made earlier: a user calling this page's button can only ever start
 * a real payment flow, never assign themselves a plan for free.
 */

import { useState, useEffect } from "react";
import apiClient from "../api/client";

export default function Billing() {
  const [subscription, setSubscription] = useState(null);
  const [plans, setPlans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [redirecting, setRedirecting] = useState(null);

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true);
      setError(null);
      try {
        const [subRes, plansRes] = await Promise.all([
          apiClient.get("/api/billing/subscription"),
          apiClient.get("/api/billing/plans"),
        ]);
        setSubscription(subRes.data?.data?.subscription || null);
        setPlans(plansRes.data?.data?.plans || []);
      } catch (err) {
        setError("Impossible de charger les informations de facturation.");
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  const handleUpgrade = async (planKey) => {
    setRedirecting(planKey);
    setError(null);
    try {
      const response = await apiClient.post("/api/billing/checkout", {
        plan: planKey,
      });
      const url = response.data?.data?.checkout_url;
      if (!url) throw new Error("No checkout URL returned");
      window.location.href = url;
    } catch (err) {
      const message =
        err.response?.data?.message || "Échec de la création de la session de paiement.";
      setError(message);
      setRedirecting(null);
    }
  };

  if (loading) {
    return (
      <div className="p-8 bg-[#fbfaf8] min-h-screen">
        <div className="text-zinc-500 text-sm">Chargement...</div>
      </div>
    );
  }

  return (
    <div className="p-8 max-w-4xl bg-[#fbfaf8] min-h-screen">
      <div className="mb-8">
        <div className="text-[#7a1730] text-xs tracking-widest uppercase mb-1">
          $ billing --status
        </div>
        <h1 className="text-2xl font-serif text-[#1a1a1a]">Facturation</h1>
      </div>

      {error && (
        <div className="bg-[#fdf0f2] border border-[#f0c3cc] text-[#7a1730] text-sm rounded px-3 py-2 mb-6">
          {error}
        </div>
      )}

      {/* Current plan */}
      {subscription && (
        <div className="bg-white border border-[#ecdfe2] rounded-lg p-5 mb-8 shadow-[0_2px_10px_rgba(122,23,48,0.05)]">
          <div className="text-xs uppercase tracking-wide text-zinc-500 mb-2">
            Plan actuel
          </div>
          <div className="flex items-center justify-between">
            <div>
              <div className="text-xl font-serif text-[#1a1a1a]">
                {subscription.plan_name || subscription.plan}
              </div>
              <div className="text-xs text-zinc-500 mt-1">
                {subscription.max_targets} targets · {subscription.max_scans_per_day} scans/jour ·{" "}
                {subscription.max_members} membre(s)
              </div>
            </div>
            <span
              className={`text-xs font-mono px-3 py-1 rounded ${
                subscription.status === "active"
                  ? "bg-[#7a1730]/10 text-[#7a1730]"
                  : "bg-amber-50 text-amber-700"
              }`}
            >
              {subscription.status}
            </span>
          </div>
        </div>
      )}

      {/* Available plans */}
      <div className="text-xs uppercase tracking-wide text-zinc-500 mb-3">
        Plans disponibles
      </div>
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {plans.map((plan) => {
          const isCurrent = subscription?.plan === plan.plan;
          const isFree = plan.plan === "free";

          return (
            <div
              key={plan.plan}
              className={`border rounded-lg p-5 flex flex-col ${
                isCurrent
                  ? "border-[#7a1730] bg-white shadow-[0_4px_16px_rgba(122,23,48,0.1)]"
                  : "border-[#ecdfe2] bg-white"
              }`}
            >
              <div className="text-[#1a1a1a] font-serif text-lg mb-1">
                {plan.name}
              </div>
              <div className="text-2xl font-mono text-[#1a1a1a] mb-3">
                {plan.price === 0 ? "Gratuit" : `$${plan.price}`}
                {plan.price > 0 && (
                  <span className="text-xs text-zinc-500 font-sans">/mois</span>
                )}
              </div>
              <div className="text-xs text-zinc-500 mb-4 flex-1">
                {plan.description}
              </div>
              <ul className="text-xs text-zinc-600 space-y-1 mb-4">
                <li>{plan.max_targets} targets</li>
                <li>{plan.scans_per_day} scans/jour</li>
                <li>{plan.max_members} membre(s)</li>
              </ul>

              {isCurrent ? (
                <div className="text-center text-xs font-mono text-[#7a1730] py-2 border border-[#7a1730] rounded">
                  Plan actuel
                </div>
              ) : isFree ? (
                <div className="text-center text-xs text-zinc-400 py-2">
                  —
                </div>
              ) : (
                <button
                  onClick={() => handleUpgrade(plan.plan)}
                  disabled={redirecting !== null}
                  className="bg-[#7a1730] hover:bg-[#5c1122] disabled:opacity-50 text-white font-semibold text-sm rounded px-3 py-2 transition-colors"
                >
                  {redirecting === plan.plan ? "Redirection..." : "Choisir ce plan"}
                </button>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}