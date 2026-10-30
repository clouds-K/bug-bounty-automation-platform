/**
 * ProtectedRoute - Guards routes that require authentication.
 *
 * Wraps <Layout /> in App.jsx. If the user is not authenticated
 * (checked via AuthContext), redirects to /login instead of
 * rendering the protected page. Without this, anyone could type
 * /dashboard, /targets, /scans, etc. directly in the URL bar and
 * see the layout/content even while logged out.
 *
 * `replace` avoids adding the blocked page to browser history, so
 * the back button doesn't bounce the user back into it.
 */

import { Navigate, Outlet } from "react-router-dom";
import { useAuth } from "../Authcontext";

export default function ProtectedRoute() {
  const { isAuthenticated, loading } = useAuth();

  // Wait for the initial /api/auth/me check to resolve before deciding
  // -- otherwise every hard refresh briefly bounces the user to /login
  // even when their cookie is still valid.
  if (loading) {
    return null; // or a spinner component
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return <Outlet />;
}