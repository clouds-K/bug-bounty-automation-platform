/**
 * AuthContext - Centralized authentication state.
 *
 * UPDATED FOR COOKIE-BASED JWT:
 *   Since the access token now lives in an httpOnly cookie, this
 *   context can no longer read it directly from localStorage/JS. Instead,
 *   on mount, it asks the backend "am I logged in?" via GET /api/auth/me
 *   -- the browser sends the cookie automatically (apiClient has
 *   withCredentials: true), and the backend's @jwt_required() either
 *   succeeds (200, user is authenticated) or fails (401).
 *
 *   login() no longer takes a token param -- the cookie is already set
 *   by the backend's Set-Cookie header on the login/register response.
 *   We just need to re-run the "am I logged in?" check (or trust the
 *   caller and set authenticated=true directly, which is what we do
 *   here for a snappier UI).
 *
 *   logout() calls the backend /api/auth/logout endpoint so it can
 *   clear the httpOnly cookies (unset_jwt_cookies) -- JS alone cannot
 *   delete an httpOnly cookie.
 */

import { createContext, useContext, useState, useEffect, useCallback } from "react";
import apiClient from "./api/client";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true); // true until the initial /me check resolves

  const checkAuth = useCallback(async () => {
    try {
      const response = await apiClient.get("/api/auth/me");
      setUser(response.data?.data?.user || null);
      setIsAuthenticated(true);
    } catch {
      setUser(null);
      setIsAuthenticated(false);
    } finally {
      setLoading(false);
    }
  }, []);

  // On first mount, ask the backend if the httpOnly cookie is valid.
  useEffect(() => {
    checkAuth();
  }, [checkAuth]);

  // Called after a successful /login or /register response (cookies
  // are already set by the backend at that point).
  const login = useCallback(async () => {
    await checkAuth();
  }, [checkAuth]);

  const logout = useCallback(async () => {
    try {
      await apiClient.post("/api/auth/logout");
    } catch {
      // Even if the request fails, clear local state -- worst case the
      // cookie lingers until it expires naturally.
    }
    setUser(null);
    setIsAuthenticated(false);
  }, []);

  // Stay in sync if apiClient's interceptor detects a 401 (session
  // expired mid-use), which happens outside React's direct control.
  useEffect(() => {
    const handleExternalLogout = () => {
      setUser(null);
      setIsAuthenticated(false);
    };
    window.addEventListener("auth:logout", handleExternalLogout);
    return () => window.removeEventListener("auth:logout", handleExternalLogout);
  }, []);

  const value = {
    isAuthenticated,
    user,
    loading,
    login,
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}