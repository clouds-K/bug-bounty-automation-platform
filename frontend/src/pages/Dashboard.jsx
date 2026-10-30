/**
 * Dashboard Page
 *
 * Aggregate overview pulled from data already available via existing
 * endpoints (no new backend routes needed): targets, scans, and
 * vulnerabilities are fetched and summarized client-side.
 */

import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import apiClient from "../api/client";

const SEVERITY_COLORS = {
  CRITICAL: "#7f1d1d",
  HIGH: "#b91c1c",
  MEDIUM: "#c2410c",
  LOW: "#a16207",
  INFO: "#a1a1aa",
};

export default function Dashboard() {
  const [targets, setTargets] = useState([]);
  const [scans, setScans] = useState([]);
  const [vulns, setVulns] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchAll = async () => {
      try {
        const [targetsRes, scansRes, vulnsRes] = await Promise.all([
          apiClient.get("/api/targets"),
          apiClient.get("/api/scans"),
          apiClient.get("/api/vulnerabilities"),
        ]);
        setTargets(targetsRes.data?.data || []);
        setScans(scansRes.data?.data || []);
        setVulns(vulnsRes.data?.data || []);
      } catch {
        // Non-blocking — each stat card just shows 0 if a fetch fails.
      } finally {
        setLoading(false);
      }
    };
    fetchAll();
  }, []);

  const activeScans = scans.filter(
    (s) => s.status === "running" || s.status === "queued"
  ).length;

  const severityCounts = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].reduce(
    (acc, sev) => {
      acc[sev] = vulns.filter(
        (v) => (v.severity || "").toUpperCase() === sev
      ).length;
      return acc;
    },
    {}
  );
  const maxSeverityCount = Math.max(...Object.values(severityCounts), 1);

  const recentScans = [...scans]
    .sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
    .slice(0, 5);

  const criticalVulns = vulns
    .filter((v) => (v.severity || "").toUpperCase() === "CRITICAL")
    .slice(0, 5);

  const targetName = (id) => {
    const t = targets.find((t) => t.id === id);
    return t?.program_name || t?.scan_url || id?.slice(0, 8) || "—";
  };

  if (loading) {
    return (
      <div className="p-8 bg-bg-black min-h-screen">
        <div className="text-zinc-500 text-sm">Chargement...</div>
      </div>
    );
  }

  return (
    <div className="p-8 bg-bg-black min-h-screen">
      <div className="mb-8">
        <div className="text-[#7a1730] text-xs tracking-widest uppercase mb-1">
          $ dashboard --overview
        </div>
        <h1 className="text-2xl font-serif text-[#1a1a1a]">Vue d'ensemble</h1>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        <Link
          to="/targets"
          className="bg-white border border-[#ecdfe2] rounded-lg p-4 hover:border-[#7a1730]/50 hover:shadow-[0_4px_16px_rgba(122,23,48,0.08)] transition-all"
        >
          <div className="text-xs uppercase tracking-wide text-zinc-500 mb-1">
            Targets
          </div>
          <div className="text-2xl font-mono text-[#1a1a1a]">
            {targets.length}
          </div>
        </Link>

        <Link
          to="/scans"
          className="bg-white border border-[#ecdfe2] rounded-lg p-4 hover:border-[#7a1730]/50 hover:shadow-[0_4px_16px_rgba(122,23,48,0.08)] transition-all"
        >
          <div className="text-xs uppercase tracking-wide text-zinc-500 mb-1">
            Scans actifs
          </div>
          <div className="text-2xl font-mono text-amber-700">
            {activeScans}
          </div>
        </Link>

        <Link
          to="/vulnerabilities"
          className="bg-white border border-[#ecdfe2] rounded-lg p-4 hover:border-[#7a1730]/50 hover:shadow-[0_4px_16px_rgba(122,23,48,0.08)] transition-all"
        >
          <div className="text-xs uppercase tracking-wide text-zinc-500 mb-1">
            Vulnérabilités
          </div>
          <div className="text-2xl font-mono text-[#1a1a1a]">
            {vulns.length}
          </div>
        </Link>

        <Link
          to="/vulnerabilities"
          className="bg-[#0d0607] border border-[#3d0c17] rounded-lg p-4 hover:border-[#7a1730] transition-colors"
        >
          <div className="text-xs uppercase tracking-wide text-zinc-500 mb-1">
            Critiques
          </div>
          <div className="text-2xl font-mono text-[#e08aa0]">
            {severityCounts.CRITICAL || 0}
          </div>
        </Link>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity breakdown */}
        <div className="bg-white border border-[#ecdfe2] rounded-lg p-5">
          <div className="text-xs uppercase tracking-wide text-zinc-500 mb-4">
            Répartition par sévérité
          </div>
          <div className="space-y-2">
            {["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((sev) => (
              <div key={sev} className="flex items-center gap-3">
                <div className="w-16 text-xs font-mono text-zinc-500 text-right">
                  {sev}
                </div>
                <div className="flex-1 h-2.5 bg-zinc-100 rounded overflow-hidden">
                  <div
                    className="h-full rounded"
                    style={{
                      width: `${((severityCounts[sev] || 0) / maxSeverityCount) * 100}%`,
                      backgroundColor: SEVERITY_COLORS[sev],
                    }}
                  />
                </div>
                <div className="w-6 text-xs font-mono text-[#1a1a1a]">
                  {severityCounts[sev] || 0}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Recent scans */}
        <div className="bg-white border border-[#ecdfe2] rounded-lg p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="text-xs uppercase tracking-wide text-zinc-500">
              Scans récents
            </div>
            <Link
              to="/scans"
              className="text-xs text-[#7a1730] hover:underline"
            >
              Voir tout →
            </Link>
          </div>
          {recentScans.length === 0 ? (
            <div className="text-sm text-zinc-400">Aucun scan récent.</div>
          ) : (
            <div className="space-y-2">
              {recentScans.map((s) => (
                <div
                  key={s.id}
                  className="flex items-center justify-between text-sm"
                >
                  <span className="text-zinc-700 font-mono text-xs truncate">
                    {targetName(s.target_id)}
                  </span>
                  <span
                    className={`text-xs px-2 py-0.5 rounded shrink-0 ml-2 ${
                      s.status === "completed"
                        ? "bg-[#7a1730]/10 text-[#7a1730]"
                        : s.status === "running"
                        ? "bg-amber-50 text-amber-700"
                        : s.status === "failed"
                        ? "bg-[#fdf0f2] text-[#7a1730]"
                        : "bg-zinc-100 text-zinc-500"
                    }`}
                  >
                    {s.status}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Critical vulnerabilities */}
      {criticalVulns.length > 0 && (
        <div className="mt-6 bg-white border border-[#7a1730]/30 rounded-lg p-5">
          <div className="flex items-center justify-between mb-4">
            <div className="text-xs uppercase tracking-wide text-[#7a1730]">
              ⚠ Vulnérabilités critiques nécessitant une action
            </div>
            <Link
              to="/vulnerabilities"
              className="text-xs text-[#7a1730] hover:underline"
            >
              Voir tout →
            </Link>
          </div>
          <div className="space-y-1">
            {criticalVulns.map((v) => (
              <div
                key={v.id}
                className="text-sm text-zinc-700 truncate"
              >
                {v.title}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}