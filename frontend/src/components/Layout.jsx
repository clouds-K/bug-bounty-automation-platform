/**
 * Layout - Shared shell for all authenticated pages.
 *
 * Wraps page content with a fixed sidebar (nav links, user info, logout)
 * and a content area. Every authenticated route renders inside this via
 * <Outlet /> (React Router's nested-route mechanism) instead of each
 * page rebuilding its own sidebar independently.
 */

import { NavLink, Outlet, useNavigate } from "react-router-dom";
import { useAuth } from "../Authcontext";

const NAV_ITEMS = [
  { to: "/dashboard", label: "Dashboard", icon: "◈" },
  { to: "/targets", label: "Targets", icon: "◎" },
  { to: "/scans", label: "Scans", icon: "◉" },
  { to: "/vulnerabilities", label: "Vulnerabilities", icon: "▲" },
  { to: "/billing", label: "Billing", icon: "$" },
];

export default function Layout() {
  const navigate = useNavigate();

  const { logout } = useAuth();
// ...
const handleLogout = async () => {
  await logout();
  navigate("/login");
};

  return (
    <div className="min-h-screen bg-[#fbfaf8] flex">
      {/* Sidebar — kept dark for contrast against the light content area */}
      <aside className="w-60 shrink-0 bg-[#0d0607] flex flex-col">
        <div className="px-6 py-7 border-b border-[#3d0c17]">
          <div className="text-[#a8324f] text-[11px] tracking-[0.2em] uppercase mb-1">
            $ platform
          </div>
          <div className="text-white font-serif text-xl tracking-wide">
            Bug Bounty
          </div>
        </div>

        <nav className="flex-1 px-3 py-6 space-y-1">
          {NAV_ITEMS.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded text-sm tracking-wide transition-colors ${
                  isActive
                    ? "bg-[#7a1730] text-white"
                    : "text-[#a1a1aa] hover:text-white hover:bg-[#1a0d10]"
                }`
              }
            >
              <span className="font-mono text-xs w-4 opacity-80">{item.icon}</span>
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div className="px-3 py-5 border-t border-[#3d0c17]">
          <button
            onClick={handleLogout}
            className="w-full flex items-center gap-3 px-3 py-2.5 rounded text-sm text-[#71717a] hover:text-[#e08aa0] hover:bg-[#1a0d10] transition-colors"
          >
            <span className="font-mono text-xs w-4">✕</span>
            Déconnexion
          </button>
        </div>
      </aside>

      {/* Main content — each page renders here via nested routing */}
      <main className="flex-1 overflow-y-auto">
        <Outlet />
      </main>
    </div>
  );
}