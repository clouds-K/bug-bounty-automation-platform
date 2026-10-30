/**
 * useScan - Encapsulates scan list fetching, auto-polling, and launch
 * logic in a single reusable hook.
 *
 * Extracted from Scans.jsx to separate UI concerns (rendering) from
 * business logic (fetching, polling cadence, launch), matching the
 * pattern described in the report's frontend architecture section.
 *
 * Usage:
 *   const { scans, loading, error, launchScan } = useScan();
 */

import { useState, useEffect, useCallback } from "react";
import apiClient from "../api/client";

const POLL_INTERVAL_MS = 8000;

export function useScan() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchScans = useCallback(async () => {
    try {
      const response = await apiClient.get("/api/scans");
      setScans(response.data?.data || []);
      setError(null);
    } catch {
      setError("Impossible de charger les scans.");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchScans();
  }, [fetchScans]);

  // Poll while any scan is still in progress, so status/progress bars
  // update without the user needing to refresh manually. Automatically
  // stops once no scan is running/queued anymore.
  useEffect(() => {
    const hasActiveScan = scans.some(
      (s) => s.status === "running" || s.status === "queued"
    );
    if (!hasActiveScan) return;

    const interval = setInterval(fetchScans, POLL_INTERVAL_MS);
    return () => clearInterval(interval);
  }, [scans, fetchScans]);

  const launchScan = useCallback(
    async ({ targetId, scanType, tags }) => {
      await apiClient.post("/api/scans", {
        target_id: targetId,
        tools: ["nuclei"],
        scan_type: scanType,
        config: tags && tags.length > 0 ? { tags } : undefined,
      });
      await fetchScans();
    },
    [fetchScans]
  );

  return { scans, loading, error, refetch: fetchScans, launchScan };
}