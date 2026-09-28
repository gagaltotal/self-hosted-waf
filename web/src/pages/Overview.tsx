import { useEffect, useState, useCallback } from "react";
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
import { api, type StatsSummary } from "../api/client";
import StatTile from "../components/StatTile";
import { CategoryBadge } from "../components/Badge";

const periods = [
  { label: "Last hour", hours: 1 },
  { label: "Last 24 hours", hours: 24 },
  { label: "Last 7 days", hours: 24 * 7 },
  { label: "Last 30 days", hours: 24 * 30 },
];

export default function Overview() {
  const [hours, setHours] = useState(24);
  const [stats, setStats] = useState<StatsSummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(() => {
    api
      .statsSummary(hours)
      .then(setStats)
      .catch(() => setError("Could not load statistics."));
  }, [hours]);

  useEffect(() => {
    load();
    const id = setInterval(load, 30_000);
    return () => clearInterval(id);
  }, [load]);

  const chartData = (stats?.timeseries ?? []).map((pt) => ({
    time: formatBucket(pt.bucket, hours),
    Blocked: pt.blocked,
    Total: pt.total,
  }));  return (
    <div className="flex flex-col gap-8">
      <div className="flex items-center justify-between">
        <h1 className="font-display text-2xl font-600 text-text">Overview</h1>
        <select
          value={hours}
          onChange={(e) => setHours(Number(e.target.value))}
          className="rounded-md border border-border bg-surface px-3 py-1.5 text-sm text-text-dim outline-none focus:border-signal-red/60"
        >
          {periods.map((p) => (
            <option key={p.hours} value={p.hours}>
              {p.label}
            </option>
          ))}
        </select>
      </div>

      {error && <p className="text-sm text-signal-red">{error}</p>}

      <div className="grid grid-cols-4 gap-4">
        <StatTile
          label="Attacks blocked"
          value={stats ? stats.blocked_requests.toLocaleString() : "–"}
          accent="red"
          hero
        />
        <StatTile
          label="Bot challenges issued"
          value={stats ? stats.challenged_count.toLocaleString() : "–"}
          accent="teal"
        />
        <StatTile
          label="Rate-limited requests"
          value={stats ? stats.rate_limited_count.toLocaleString() : "–"}
          accent="amber"
        />
        <StatTile
          label="Total flagged requests"
          value={stats ? stats.total_requests.toLocaleString() : "–"}
          accent="neutral"
        />
      </div>

      <section className="border border-border bg-surface p-5">
        <h2 className="mb-4 text-sm font-medium text-text-dim">Flagged traffic over time</h2>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chartData}>
              <defs>
                <linearGradient id="blockedFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#FF5A5A" stopOpacity={0.35} />
                  <stop offset="100%" stopColor="#FF5A5A" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid stroke="#242B38" vertical={false} />
              <XAxis
                dataKey="time"
                stroke="#4E5768"
                tick={{ fill: "#8993A4", fontSize: 12 }}
                tickLine={false}
                axisLine={{ stroke: "#242B38" }}
              />
              <YAxis
                stroke="#4E5768"
                tick={{ fill: "#8993A4", fontSize: 12 }}
                tickLine={false}
                axisLine={false}
                allowDecimals={false}
              />
              <Tooltip
                contentStyle={{
                  background: "#191F29",
                  border: "1px solid #242B38",
                  borderRadius: 6,
                  fontSize: 13,
                }}
                labelStyle={{ color: "#E7E9EC" }}
              />
              <Area
                type="monotone"
                dataKey="Blocked"
                stroke="#FF5A5A"
                fill="url(#blockedFill)"
                strokeWidth={2}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </section>

      <div className="grid grid-cols-2 gap-6">
        <section className="border border-border bg-surface p-5">
          <h2 className="mb-4 text-sm font-medium text-text-dim">By category</h2>
          {stats && Object.keys(stats.by_category ?? {}).length > 0 ? (
            <ul className="flex flex-col gap-3">
              {Object.entries(stats.by_category ?? {})
                .sort((a, b) => b[1] - a[1])
                .map(([cat, count]) => (
                  <li key={cat} className="flex items-center justify-between">
                    <CategoryBadge category={cat} />
                    <span className="font-mono text-sm text-text-dim">{count.toLocaleString()}</span>
                  </li>
                ))}
            </ul>
          ) : (
            <EmptyNote text="No flagged requests in this period." />
          )}
        </section>

        <section className="border border-border bg-surface p-5">
          <h2 className="mb-4 text-sm font-medium text-text-dim">Top source IPs</h2>
          {stats && (stats.top_ips ?? []).length > 0 ? (
            <ul className="flex flex-col gap-3">
              {(stats.top_ips ?? []).map((ip) => (
                <li key={ip.ip} className="flex items-center justify-between">
                  <span className="font-mono text-sm text-text">{ip.ip}</span>
                  <span className="font-mono text-sm text-text-dim">{ip.count.toLocaleString()}</span>
                </li>
              ))}
            </ul>
          ) : (
            <EmptyNote text="No flagged source IPs in this period." />
          )}
        </section>
      </div>
    </div>
  );
}

function EmptyNote({ text }: { text: string }) {
  return <p className="text-sm text-text-faint">{text}</p>;
}

function formatBucket(iso: string, hours: number): string {
  const d = new Date(iso);
  if (hours > 24 * 2) {
    return d.toLocaleDateString(undefined, { month: "short", day: "numeric" });
  }
  return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}
