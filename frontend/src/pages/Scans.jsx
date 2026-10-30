/**
 * Scans Page
 *
 * Lists scans across all targets and lets the user launch a new one.
 * Scans run asynchronously via Celery on the backend (see scanner.py),
 * so this page polls for status updates on any RUNNING/QUEUED scan
 * instead of assuming completion right after the POST returns --
 * matches how scans actually behaved throughout backend testing
 * (a "quick" scan with tags still took several minutes).
 */

import { useState, useEffect, useCallback } from "react";
import apiClient from "../api/client";

const AVAILABLE_TAGS = ["cve", "exposure", "misconfig"];
const POLL_INTERVAL_MS = 8000;

const STATUS_STYLES = {
  queued: "bg-zinc-100 text-zinc-500",
  running: "bg-amber-50 text-amber-700",
  completed: "bg-[#7a1730]/10 text-[#7a1730]",
  failed: "bg-[#fdf0f2] text-[#7a1730]",
  cancelled: "bg-zinc-100 text-zinc-400",
};

export default function Scans() {
  const [scans, setScans] = useState([]);
  const [targets, setTargets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [showForm, setShowForm] = useState(false);
  const [targetId, setTargetId] = useState("");
  const [scanType, setScanType] = useState("quick");
  const [selectedTags, setSelectedTags] = useState(["cve"]);
  const [submitting, setSubmitting] = useState(false);

  const fetchScans = useCallback(async () => {
    try {
      const response = await apiClient.get("/api/scans");
      setScans(response.data?.data || []);
    } catch (err) {
      setError("Impossible de charger les scans.");
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchTargets = useCallback(async () => {
    try {
      const response = await apiClient.get("/api/targets");
      const list = response.data?.data || [];
      setTargets(list);
      if (list.length > 0) setTargetId((prev) => prev || list[0].id);
    } catch {
      // Non-blocking — the launch form just won't have options.
    }
  }, []);

  useEffect(() => {
    fetchScans();
    fetchTargets();
  }, [fetchScans, fetchTargets]);

  // Poll while any scan is still in progress, so status/progress bars
  // update without the user needing to refresh manually.
  useEffect(() => {
    const hasActiveScan = scans.some(
      (s) => s.status === "running" || s.status === "queued"
    );
    if (!hasActiveScan) return;

    const interval = setInterval(fetchScans, POLL_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [scans, fetchScans]);

  const toggleTag = (tag) => {
    setSelectedTags((prev) =>
      prev.includes(tag) ? prev.filter((t) => t !== tag) : [...prev, tag]
    );
  };

  const handleLaunch = async (e) => {
    e.preventDefault();
    if (!targetId) return;

    setSubmitting(true);
    setError(null);

    try {
      await apiClient.post("/api/scans", {
        target_id: targetId,
        tools: ["nuclei"],
        scan_type: scanType,
        config: selectedTags.length > 0 ? { tags: selectedTags } : undefined,
      });
      setShowForm(false);
      fetchScans();
    } catch (err) {
      const message =
        err.response?.data?.message || "Échec du lancement du scan.";
      setError(message);
    } finally {
      setSubmitting(false);
    }
  };

  const targetName = (id) => {
    const t = targets.find((t) => t.id === id);
    return t?.program_name || t?.scan_url || id.slice(0, 8);
  };

  return (
    <div className="p-8 bg-[#fbfaf8] min-h-screen">
      <div className="flex items-center justify-between mb-6">
        <div>
          <div className="text-[#7a1730] text-xs tracking-widest uppercase mb-1">
            $ scans --list
          </div>
          <h1 className="text-2xl font-serif text-[#1a1a1a]">Scans</h1>
        </div>
        <button
          onClick={() => setShowForm((v) => !v)}
          disabled={targets.length === 0}
          className="bg-[#7a1730] hover:bg-[#5c1122] disabled:opacity-40 disabled:cursor-not-allowed text-white font-semibold text-sm rounded px-4 py-2 transition-colors"
        >
          {showForm ? "Annuler" : "+ Lancer un scan"}
        </button>
      </div>

      {targets.length === 0 && !loading && (
        <div className="text-zinc-500 text-sm mb-4">
          Aucun target disponible — crée d'abord un target avant de lancer un scan.
        </div>
      )}

      {error && (
        <div className="bg-[#fdf0f2] border border-[#f0c3cc] text-[#7a1730] text-sm rounded px-3 py-2 mb-4">
          {error}
        </div>
      )}

      {showForm && (
        <form
          onSubmit={handleLaunch}
          className="bg-white border border-[#ecdfe2] rounded-lg p-5 mb-6 space-y-4 shadow-[0_2px_10px_rgba(122,23,48,0.05)]"
        >
          <div>
            <label className="block text-xs uppercase tracking-wide text-zinc-500 mb-1">
              Target
            </label>
            <select
              value={targetId}
              onChange={(e) => setTargetId(e.target.value)}
              className="w-full bg-white border border-zinc-300 rounded px-3 py-2 text-[#1a1a1a] text-sm focus:outline-none focus:border-[#7a1730]"
            >
              {targets.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.program_name || t.scan_url}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="block text-xs uppercase tracking-wide text-zinc-500 mb-1">
              Type de scan
            </label>
            <div className="flex gap-2">
              {["quick", "full"].map((type) => (
                <button
                  key={type}
                  type="button"
                  onClick={() => setScanType(type)}
                  className={`px-3 py-1.5 rounded text-sm border transition-colors ${
                    scanType === type
                      ? "bg-[#7a1730]/10 border-[#7a1730] text-[#7a1730]"
                      : "border-zinc-200 text-zinc-500 hover:text-zinc-700"
                  }`}
                >
                  {type === "quick" ? "Rapide (tags ciblés)" : "Complet"}
                </button>
              ))}
            </div>
          </div>

          {scanType === "quick" && (
            <div>
              <label className="block text-xs uppercase tracking-wide text-zinc-500 mb-1">
                Tags Nuclei
              </label>
              <div className="flex gap-2 flex-wrap">
                {AVAILABLE_TAGS.map((tag) => (
                  <button
                    key={tag}
                    type="button"
                    onClick={() => toggleTag(tag)}
                    className={`px-3 py-1 rounded text-xs font-mono border transition-colors ${
                      selectedTags.includes(tag)
                        ? "bg-[#7a1730]/10 border-[#7a1730] text-[#7a1730]"
                        : "border-zinc-200 text-zinc-500 hover:text-zinc-700"
                    }`}
                  >
                    {tag}
                  </button>
                ))}
              </div>
            </div>
          )}

          <button
            type="submit"
            disabled={submitting || !targetId}
            className="bg-[#7a1730] hover:bg-[#5c1122] disabled:opacity-50 text-white font-semibold text-sm rounded px-4 py-2 transition-colors"
          >
            {submitting ? "Lancement..." : "Lancer le scan"}
          </button>
        </form>
      )}

      {loading ? (
        <div className="text-zinc-500 text-sm">Chargement...</div>
      ) : scans.length === 0 ? (
        <div className="text-zinc-500 text-sm">Aucun scan pour le moment.</div>
      ) : (
        <div className="border border-[#ecdfe2] rounded-lg overflow-hidden bg-white">
          <table className="w-full text-sm">
            <thead className="bg-[#faf5f6] text-zinc-500 text-xs uppercase tracking-wide">
              <tr>
                <th className="text-left px-4 py-3">Target</th>
                <th className="text-left px-4 py-3">Statut</th>
                <th className="text-left px-4 py-3">Progrès</th>
                <th className="text-left px-4 py-3">Vulnérabilités</th>
                <th className="text-left px-4 py-3">Créé le</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((s) => (
                <tr
                  key={s.id}
                  className="border-t border-[#ecdfe2] text-zinc-700 hover:bg-[#fbfaf8]"
                >
                  <td className="px-4 py-3 font-mono text-xs text-zinc-500">
                    {targetName(s.target_id)}
                  </td>
                  <td className="px-4 py-3">
                    <span
                      className={`text-xs px-2 py-0.5 rounded ${
                        STATUS_STYLES[s.status] || "bg-zinc-100 text-zinc-500"
                      }`}
                    >
                      {s.status}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="w-24 h-1.5 bg-zinc-100 rounded overflow-hidden">
                      <div
                        className="h-full bg-[#7a1730] transition-all"
                        style={{ width: `${s.progress || 0}%` }}
                      />
                    </div>
                  </td>
                  <td className="px-4 py-3">{s.vulnerabilities_found ?? "—"}</td>
                  <td className="px-4 py-3 text-xs text-zinc-500">
                    {new Date(s.created_at).toLocaleString("fr-FR")}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}