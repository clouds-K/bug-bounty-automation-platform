/**
 * API Client - Centralized axios instance for all backend calls.
 *
 * AUTH MODEL (updated for cookie-based JWT):
 *   The backend now issues the JWT as an httpOnly cookie (see auth.py's
 *   set_access_cookies / set_refresh_cookies) instead of returning it in
 *   the JSON body. This means:
 *     - JS can no longer read the token (protects against XSS token theft)
 *     - `withCredentials: true` is required so the browser sends the
 *       cookie automatically on every request -- no more manual
 *       Authorization header
 *     - flask-jwt-extended requires a CSRF double-submit token for any
 *       cookie-authenticated state-changing request. It sets a second,
 *       NON-httpOnly cookie ("csrf_access_token") specifically so JS can
 *       read it and echo it back in a header. We do that below.
 */

import axios from "axios";

const API_URL = import.meta.env.VITE_API_URL || "";

const apiClient = axios.create({
  baseURL: API_URL,
  withCredentials: true, // send/receive the httpOnly JWT cookies
  headers: {
    "Content-Type": "application/json",
  },
});

// Read a cookie value by name (only works for non-httpOnly cookies,
// which is exactly what csrf_access_token is designed to be).
function getCookie(name) {
  const match = document.cookie.match(
    new RegExp("(^| )" + name + "=([^;]+)")
  );
  return match ? decodeURIComponent(match[2]) : null;
}

// Attach the CSRF token to state-changing requests. GET/HEAD/OPTIONS
// don't need it -- CSRF protection only matters for requests that
// change server state.
apiClient.interceptors.request.use((config) => {
  const method = (config.method || "get").toLowerCase();
  if (!["get", "head", "options"].includes(method)) {
    const csrfToken = getCookie("csrf_access_token");
    if (csrfToken) {
      config.headers["X-CSRF-TOKEN"] = csrfToken;
    }
  }
  return config;
});

// If the backend ever responds 401 (token expired/invalid/missing),
// notify AuthContext so the app re-renders into its logged-out state.
// The actual redirect to /login is handled by ProtectedRoute.
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      window.dispatchEvent(new Event("auth:logout"));
    }
    return Promise.reject(error);
  }
);

export default apiClient;