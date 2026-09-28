import { type ReactNode } from "react";
import { NavLink, useNavigate } from "react-router-dom";
import { Shield, Gauge, Globe2, ScrollText, LogOut } from "lucide-react";
import { useAuth } from "../context/AuthContext";

const navItems = [
  { to: "/", label: "Overview", icon: Gauge, end: true },
  { to: "/sites", label: "Sites", icon: Globe2, end: false },
  { to: "/logs", label: "Logs", icon: ScrollText, end: false },
];

export default function Layout({ children }: { children: ReactNode }) {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  async function handleLogout() {
    await logout();
    navigate("/login", { replace: true });
  }

  return (
    <div className="flex min-h-screen bg-bg">
      <aside className="flex w-60 shrink-0 flex-col border-r border-border px-4 py-6">
        <div className="mb-8 flex items-center gap-2 px-2">
          <Shield className="h-5 w-5 text-signal-red" strokeWidth={2.25} />
          <span className="font-display text-[15px] font-600 tracking-tight text-text">
            WAF Console
          </span>
        </div>

        <nav className="flex flex-1 flex-col gap-1">
          {navItems.map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                `flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors ${
                  isActive
                    ? "bg-surface-2 text-text"
                    : "text-text-dim hover:bg-surface hover:text-text"
                }`
              }
            >
              <Icon className="h-4 w-4" strokeWidth={2} />
              {label}
            </NavLink>
          ))}
        </nav>

        <div className="mt-auto border-t border-border pt-4">
          <div className="mb-2 truncate px-2 text-xs text-text-faint" title={user?.email}>
            {user?.email}
          </div>
          <button
            onClick={handleLogout}
            className="flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm text-text-dim transition-colors hover:bg-surface hover:text-text"
          >
            <LogOut className="h-4 w-4" strokeWidth={2} />
            Sign out
          </button>
        </div>
      </aside>

      <main className="min-w-0 flex-1 overflow-y-auto">
        <div className="mx-auto max-w-6xl px-8 py-8">{children}</div>
      </main>
    </div>
  );
}
