/**
 * Targets Page
 *
 * Lists all targets for the current organization, allows creating a new
 * one, and lets the user generate + download a PDF vulnerability report
 * per target.
 *
 * PDF REPORT FLOW:
 *   1. POST /api/targets/<id>/generate-report -> { task_id }, returns
 *      immediately (202) while WeasyPrint runs on the Ubuntu Celery
 *      worker in the background.
 *   2. Poll GET /api/targets/report-status/<task_id> every few seconds
 *      until status is "completed" (or "failed").
 *   3. On completion, trigger GET /api/targets/report-download/<task_id>
 *      as a real browser download (the backend streams base64-decoded
 *      PDF bytes directly from the Celery/Redis result -- see
 *      report_tasks.py for why no shared filesystem path is needed).
 */

import { useState, useEffect, useRef } from "react";
import apiClient from "../api/client";

const POLL_INTERVAL_MS = 3000;

export default function Targets() {
  const [targets, setTargets] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [showForm, setShowForm] = useState(false);
  const [formData, setFormData] = useState({ scan_url: "", program_name: "" });
  const [submitting, setSubmitting] = useState(false);

  // Tracks report generation state per target: { [targetId]: "pending" | "completed" | "failed" }
  const [reportStatus, setReportStatus] = useState({});
  const pollTimers = useRef({});

  const fetchTargets = async () => {
    setLoading(true);
    setError(null);
    try {
      const response = await apiClient.get("/api/targets");
      setTargets(response.data?.data || []);
    } catch (err) {
      setError("Impossible de charger les targets.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchTargets();
    // Clean up any in-flight polling timers if the page unmounts.
    return () => {
      Object.values(pollTimers.current).forEach(clearInterval);
    };
  }, []);

  const handleCreate = async (e) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);

    try {
      await apiClient.post("/api/targets", {
        scan_url: formData.scan_url,
        program_name: formData.program_name || undefined,
        scan_enabled: true,
      });
      setFormData({ scan_url: "", program_name: "" });
      setShowForm(false);
      fetchTargets();
    } catch (err) {
      const message =
        err.response?.data?.message || "Échec de la création du target.";
      setError(message);
    } finally {
      setSubmitting(false);
    }
  };

  const downloadReport = async (targetId, taskId) => {
    try {
      const response = await apiClient.get(
        `/api/targets/report-download/${taskId}`,
        { responseType: "blob" }
      );
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", `security_report_${targetId.slice(0, 8)}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch {
      setReportStatus((prev) => ({ ...prev, [targetId]: "failed" }));
    }
  };

  const pollReportStatus = (targetId, taskId) => {
    pollTimers.current[targetId] = setInterval(async () => {
      try {
        const response = await apiClient.get(
          `/api/targets/report-status/${taskId}`
        );
        const status = response.data?.data?.status;

        if (status === "completed") {
          clearInterval(pollTimers.current[targetId]);
          setReportStatus((prev) => ({ ...prev, [targetId]: "completed" }));
          downloadReport(targetId, taskId);
        } else if (status === "failed") {
          clearInterval(pollTimers.current[targetId]);
          setReportStatus((prev) => ({ ...prev, [targetId]: "failed" }));
        }
        // else still "pending" -- keep polling
      } catch {
        clearInterval(pollTimers.current[targetId]);
        setReportStatus((prev) => ({ ...prev, [targetId]: "failed" }));
      }
    }, POLL_INTERVAL_MS);
  };

  const handleGenerateReport = async (targetId) => {
    setReportStatus((prev) => ({ ...prev, [targetId]: "pending" }));
    try {
      const response = await apiClient.post(
        `/api/targets/${targetId}/generate-report`
      );
      const taskId = response.data?.data?.task_id;
      if (!taskId) throw new Error("No task_id returned");
      pollReportStatus(targetId, taskId);
    } catch {
      setReportStatus((prev) => ({ ...prev, [targetId]: "failed" }));
    }
  };

  const reportButtonLabel = (targetId) => {
    const status = reportStatus[targetId];
    if (status === "pending") return "Génération...";
    if (status === "failed") return "Échec — Réessayer";
    return "Générer PDF";
  };

  return (
    <div className="p-8 bg-[#fbfaf8] min-h-screen">
      <div className="flex items-center justify-between mb-6">
        <div>
          <div className="text-[#7a1730] text-xs tracking-widest uppercase mb-1">
            $ targets --list
          </div>
          <h1 className="text-2xl font-serif text-[#1a1a1a]">Targets</h1>
        </div>
        <button
          onClick={() => setShowForm((v) => !v)}
          className="bg-[#7a1730] hover:bg-[#5c1122] text-white font-semibold text-sm rounded px-4 py-2 transition-colors"
        >
          {showForm ? "Annuler" : "+ Nouveau target"}
        </button>
      </div>

      {error && (
        <div className="bg-[#fdf0f2] border border-[#f0c3cc] text-[#7a1730] text-sm rounded px-3 py-2 mb-4">
          {error}
        </div>
      )}

      {showForm && (
        <form
          onSubmit={handleCreate}
          className="bg-white border border-[#ecdfe2] rounded-lg p-5 mb-6 space-y-3 shadow-[0_2px_10px_rgba(122,23,48,0.05)]"
        >
          <div>
            <label className="block text-xs uppercase tracking-wide text-zinc-500 mb-1">
              Scan URL *
            </label>
            <input
              type="text"
              required
              value={formData.scan_url}
              onChange={(e) =>
                setFormData({ ...formData, scan_url: e.target.value })
              }
              placeholder="http://192.168.56.106"
              className="w-full bg-white border border-zinc-300 rounded px-3 py-2 text-[#1a1a1a] text-sm focus:outline-none focus:border-[#7a1730] focus:ring-1 focus:ring-[#7a1730]/30"
            />
          </div>
          <div>
            <label className="block text-xs uppercase tracking-wide text-zinc-500 mb-1">
              Nom du programme
            </label>
            <input
              type="text"
              value={formData.program_name}
              onChange={(e) =>
                setFormData({ ...formData, program_name: e.target.value })
              }
              placeholder="Metasploitable2"
              className="w-full bg-white border border-zinc-300 rounded px-3 py-2 text-[#1a1a1a] text-sm focus:outline-none focus:border-[#7a1730] focus:ring-1 focus:ring-[#7a1730]/30"
            />
          </div>
          <button
            type="submit"
            disabled={submitting}
            className="bg-[#7a1730] hover:bg-[#5c1122] disabled:opacity-50 text-white font-semibold text-sm rounded px-4 py-2 transition-colors"
          >
            {submitting ? "Création..." : "Créer le target"}
          </button>
        </form>
      )}

      {loading ? (
        <div className="text-zinc-500 text-sm">Chargement...</div>
      ) : targets.length === 0 ? (
        <div className="text-zinc-500 text-sm">
          Aucun target pour le moment. Crées-en un pour commencer à scanner.
        </div>
      ) : (
        <div className="border border-[#ecdfe2] rounded-lg overflow-hidden bg-white">
          <table className="w-full text-sm">
            <thead className="bg-[#faf5f6] text-zinc-500 text-xs uppercase tracking-wide">
              <tr>
                <th className="text-left px-4 py-3">Nom</th>
                <th className="text-left px-4 py-3">URL</th>
                <th className="text-left px-4 py-3">Statut</th>
                <th className="text-left px-4 py-3">Vulnérabilités</th>
                <th className="text-left px-4 py-3">Rapport</th>
              </tr>
            </thead>
            <tbody>
              {targets.map((t) => {
                const status = reportStatus[t.id];
                return (
                  <tr
                    key={t.id}
                    className="border-t border-[#ecdfe2] text-zinc-700 hover:bg-[#fbfaf8]"
                  >
                    <td className="px-4 py-3">{t.program_name || "—"}</td>
                    <td className="px-4 py-3 font-mono text-xs text-zinc-500">
                      {t.scan_url}
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={`text-xs px-2 py-0.5 rounded ${
                          t.scan_enabled
                            ? "bg-[#7a1730]/10 text-[#7a1730]"
                            : "bg-zinc-100 text-zinc-500"
                        }`}
                      >
                        {t.scan_enabled ? "Actif" : "En pause"}
                      </span>
                    </td>
                    <td className="px-4 py-3">{t.vuln_count_total ?? "—"}</td>
                    <td className="px-4 py-3">
                      <button
                        onClick={() => handleGenerateReport(t.id)}
                        disabled={status === "pending"}
                        className={`text-xs font-mono px-3 py-1.5 rounded border transition-colors ${
                          status === "failed"
                            ? "border-[#7a1730] text-[#7a1730] hover:bg-[#fdf0f2]"
                            : status === "pending"
                            ? "border-zinc-200 text-zinc-400 cursor-wait"
                            : "border-[#7a1730]/40 text-[#7a1730] hover:bg-[#7a1730]/5"
                        }`}
                      >
                        {reportButtonLabel(t.id)}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}