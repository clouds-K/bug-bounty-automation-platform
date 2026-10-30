/**
 * Vulnerabilities Page
 *
 * Lists all vulnerabilities across targets, with severity filtering and
 * a detail panel showing CVSS/EPSS/CWE data pulled from evidence.nvd
 * (populated by app/services/nvd_service.py during scans).
 *
 * CWE display: evidence.nvd.cwe_id (official NVD data) always takes
 * priority over vuln.cwe_id when the latter is only an ML estimate
 * (vuln.cwe_source === "ml_estimate", set by app/services/ml_service.py
 * at creation time). See getCweInfo() below.
 */

import { useState, useEffect, useCallback } from "react";
import apiClient from "../api/client";

const SEVERITY_COLORS = {
  CRITICAL: "#7f1d1d",
  HIGH: "#b91c1c",
  MEDIUM: "#c2410c",
  LOW: "#a16207",
  INFO: "#a1a1aa",
};

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

function parseNvd(evidence) {
  if (!evidence) return null;
  try {
    const parsed = JSON.parse(evidence);
    return parsed.nvd || null;
  } catch {
    return null;
  }
}

/**
 * Resolves the CWE to display for a vulnerability, and its source.
 * NVD's official CWE (evidence.nvd.cwe_id) wins whenever present;
 * otherwise falls back to vuln.cwe_id, which may be an ML estimate.
 */
function getCweInfo(v) {
  const nvd = parseNvd(v.evidence);
  if (nvd?.cwe_id) return { cweId: nvd.cwe_id, source: "nvd_official" };
  if (v.cwe_id) return { cweId: v.cwe_id, source: v.cwe_source };
  return null;
}

function CweBadge({ cweId, source }) {
  if (!cweId) return null;
  const isMl = source === "ml_estimate";
  return (
    <span
      className={`text-xs font-mono px-2 py-0.5 rounded border shrink-0 ${
        isMl
          ? "bg-amber-50 text-amber-700 border-amber-200"
          : "bg-zinc-100 text-zinc-700 border-zinc-200"
      }`}
      title={isMl ? "Estimation IA (non vérifiée NVD)" : "CWE officiel NVD"}
    >
      {cweId}
      {isMl && <span className="opacity-70"> · IA</span>}
    </span>
  );
}

export default function Vulnerabilities() {
  const [vulns, setVulns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [severityFilter, setSeverityFilter] = useState("all");
  const [selected, setSelected] = useState(null);

  const fetchVulns = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const params = {};
      if (severityFilter !== "all") params.severity = severityFilter;
      const response = await apiClient.get("/api/vulnerabilities", { params });
      setVulns(response.data?.data || []);
    } catch (err) {
      setError("Impossible de charger les vulnérabilités.");
    } finally {
      setLoading(false);
    }
  }, [severityFilter]);

  useEffect(() => {
    fetchVulns();
  }, [fetchVulns]);

  const counts = SEVERITY_ORDER.reduce((acc, sev) => {
    acc[sev] = vulns.filter((v) => (v.severity || "").toUpperCase() === sev).length;
    return acc;
  }, {});

  return (
    <div className="p-8 flex gap-6 bg-[#fbfaf8] min-h-screen">
      {/* Main list */}
      <div className="flex-1 min-w-0">
        <div className="mb-6">
          <div className="text-[#7a1730] text-xs tracking-widest uppercase mb-1">
            $ vulnerabilities --list
          </div>
          <h1 className="text-2xl font-serif text-[#1a1a1a]">Vulnerabilities</h1>
        </div>

        {/* Severity filter bar */}
        <div className="flex gap-2 mb-4 flex-wrap">
          <button
            onClick={() => setSeverityFilter("all")}
            className={`px-3 py-1.5 rounded text-xs font-mono border transition-colors ${
              severityFilter === "all"
                ? "bg-[#1a1a1a] border-[#1a1a1a] text-white"
                : "border-zinc-200 text-zinc-500 hover:text-zinc-700"
            }`}
          >
            TOUTES ({vulns.length})
          </button>
          {SEVERITY_ORDER.map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev.toLowerCase())}
              className="px-3 py-1.5 rounded text-xs font-mono border transition-colors"
              style={{
                borderColor:
                  severityFilter === sev.toLowerCase()
                    ? SEVERITY_COLORS[sev]
                    : "#e4e4e7",
                color:
                  severityFilter === sev.toLowerCase()
                    ? SEVERITY_COLORS[sev]
                    : "#71717a",
                backgroundColor:
                  severityFilter === sev.toLowerCase()
                    ? `${SEVERITY_COLORS[sev]}15`
                    : "transparent",
              }}
            >
              {sev} ({counts[sev]})
            </button>
          ))}
        </div>

        {error && (
          <div className="bg-[#fdf0f2] border border-[#f0c3cc] text-[#7a1730] text-sm rounded px-3 py-2 mb-4">
            {error}
          </div>
        )}

        {loading ? (
          <div className="text-zinc-500 text-sm">Chargement...</div>
        ) : vulns.length === 0 ? (
          <div className="text-zinc-500 text-sm">Aucune vulnérabilité trouvée.</div>
        ) : (
          <div className="space-y-2">
            {vulns.map((v) => {
              const sevKey = (v.severity || "INFO").toUpperCase();
              const isSelected = selected?.id === v.id;
              const cwe = getCweInfo(v);
              return (
                <button
                  key={v.id}
                  onClick={() => setSelected(v)}
                  className={`w-full text-left border rounded-lg overflow-hidden flex transition-colors bg-white ${
                    isSelected
                      ? "border-[#7a1730]"
                      : "border-[#ecdfe2] hover:bg-[#fbfaf8]"
                  }`}
                >
                  <div
                    className="w-1.5 shrink-0"
                    style={{ backgroundColor: SEVERITY_COLORS[sevKey] }}
                  />
                  <div className="flex-1 px-4 py-3 min-w-0">
                    <div className="flex items-center justify-between gap-3">
                      <div className="text-[#1a1a1a] text-sm truncate">
                        {v.title}
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
  {v.cvss_score != null && (
    <span className="font-mono text-xs text-zinc-500">
      CVSS {v.cvss_score}
    </span>
  )}
  {(() => {
    const nvd = parseNvd(v.evidence);
    return nvd?.cve_id ? (
      <span className="font-mono text-xs text-zinc-500">{nvd.cve_id}</span>
    ) : null;
  })()}
                        {cwe && <CweBadge cweId={cwe.cweId} source={cwe.source} />}
                        <span
                          className="text-xs font-mono px-2 py-0.5 rounded"
                          style={{
                            backgroundColor: `${SEVERITY_COLORS[sevKey]}18`,
                            color: SEVERITY_COLORS[sevKey],
                          }}
                        >
                          {sevKey}
                        </span>
                      </div>
                    </div>
                    <div className="text-xs text-zinc-500 font-mono mt-1 truncate">
                      {v.url}
                    </div>
                  </div>
                </button>
              );
            })}
          </div>
        )}
      </div>

      {/* Detail panel */}
      {selected && (
        <div className="w-96 shrink-0 border border-[#ecdfe2] rounded-lg bg-white p-5 h-fit sticky top-8 shadow-[0_4px_20px_rgba(122,23,48,0.06)]">
          <button
            onClick={() => setSelected(null)}
            className="text-zinc-400 hover:text-zinc-600 text-xs mb-3"
          >
            ✕ Fermer
          </button>
          <h2 className="text-[#1a1a1a] font-serif text-base mb-3">
            {selected.title}
          </h2>

          <div className="flex gap-2 flex-wrap mb-4">
            <span
              className="text-xs font-mono px-2 py-0.5 rounded"
              style={{
                backgroundColor: `${SEVERITY_COLORS[(selected.severity || "INFO").toUpperCase()]}18`,
                color: SEVERITY_COLORS[(selected.severity || "INFO").toUpperCase()],
              }}
            >
              {(selected.severity || "info").toUpperCase()}
            </span>
            {selected.cvss_score != null && (
              <span className="text-xs font-mono px-2 py-0.5 rounded bg-[#faf5f6] text-[#7a1730]">
                CVSS {selected.cvss_score}
              </span>
            )}
            {(() => {
              const nvd = parseNvd(selected.evidence);
              return nvd?.cve_id ? (
               <span className="text-xs font-mono px-2 py-0.5 rounded bg-zinc-100 text-zinc-700 border border-zinc-200">
                   {nvd.cve_id}
              </span>
                                     ) : null;
                })()}
            {(() => {
              const nvd = parseNvd(selected.evidence);
              return nvd?.epss_score ? (
                <span className="text-xs font-mono px-2 py-0.5 rounded bg-amber-50 text-amber-700">
                  EPSS {(nvd.epss_score * 100).toFixed(1)}%
                </span>
              ) : null;
            })()}
            {(() => {
              const cwe = getCweInfo(selected);
              return cwe ? <CweBadge cweId={cwe.cweId} source={cwe.source} /> : null;
            })()}
          </div>

          {selected.description && (
            <div className="mb-4">
              <div className="text-xs uppercase tracking-wide text-zinc-500 mb-1">
                Description
              </div>
              <p className="text-sm text-zinc-700">{selected.description}</p>
            </div>
          )}

          <div className="mb-4">
            <div className="text-xs uppercase tracking-wide text-zinc-500 mb-1">
              URL affectée
            </div>
            <p className="text-xs font-mono text-zinc-600 break-all">
              {selected.url}
            </p>
          </div>

          {selected.remediation && (
            <div className="mb-4">
              <div className="text-xs uppercase tracking-wide text-zinc-500 mb-1">
                Remédiation
              </div>
              <p className="text-sm text-zinc-700">{selected.remediation}</p>
            </div>
          )}

          {(() => {
            const nvd = parseNvd(selected.evidence);
            if (!nvd?.references?.length) return null;
            return (
              <div>
                <div className="text-xs uppercase tracking-wide text-zinc-500 mb-1">
                  Références
                </div>
                <ul className="space-y-1">
                  {nvd.references.slice(0, 3).map((ref, i) => (
                    <li key={i}>
                      <a
                        href={ref}
                        target="_blank"
                        rel="noreferrer"
                        className="text-xs text-[#7a1730] hover:underline break-all"
                      >
                        {ref}
                      </a>
                    </li>
                  ))}
                </ul>
              </div>
            );
          })()}
        </div>
      )}
    </div>
  );
}