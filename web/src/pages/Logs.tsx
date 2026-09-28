import { useEffect, useState } from "react";
import { ChevronLeft, ChevronRight, X } from "lucide-react";
import { api, type AttackLog, type Site } from "../api/client";
import { CategoryBadge, ActionBadge } from "../components/Badge";

const PAGE_SIZE = 25;

export default function Logs() {
  const [sites, setSites] = useState<Site[]>([]);
  const [logs, setLogs] = useState<AttackLog[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [selected, setSelected] = useState<AttackLog | null>(null);

  const [siteId, setSiteId] = useState("");
  const [category, setCategory] = useState("");
  const [action, setAction] = useState("");
  const [clientIP, setClientIP] = useState("");

  useEffect(() => {
    api.listSites().then((res) => setSites(res ?? [])).catch(() => {});
  }, []);

  useEffect(() => {
    api
      .listLogs({
        site_id: siteId || undefined,
        category: category || undefined,
        action: action || undefined,
        client_ip: clientIP || undefined,
        limit: PAGE_SIZE,
        offset: page * PAGE_SIZE,
      })
      .then((res) => {
        setLogs(res.logs ?? []);
        setTotal(res.total ?? 0);
      })
      .catch(() => setError("Could not load logs."));
  }, [siteId, category, action, clientIP, page]);

  function resetToFirstPage<T>(setter: (v: T) => void) {
    return (v: T) => {
      setter(v);
      setPage(0);
    };
  }

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div className="flex flex-col gap-6">
      <h1 className="font-display text-2xl font-600 text-text">Attack logs</h1>

      <div className="flex flex-wrap items-center gap-3">
        <select
          value={siteId}
          onChange={(e) => resetToFirstPage(setSiteId)(e.target.value)}
          className={selectCls}
        >
          <option value="">All sites</option>
          {sites.map((s) => (
            <option key={s.id} value={s.id}>
              {s.name}
            </option>
          ))}
        </select>

        <select
          value={category}
          onChange={(e) => resetToFirstPage(setCategory)(e.target.value)}
          className={selectCls}
        >
          <option value="">All categories</option>
          <option value="sqli">SQL injection</option>
          <option value="xss">XSS</option>
          <option value="cmdi">Command injection</option>
          <option value="path_traversal">Path traversal</option>
          <option value="rate_limit">Rate limit</option>
          <option value="bot">Bot</option>
        </select>

        <select
          value={action}
          onChange={(e) => resetToFirstPage(setAction)(e.target.value)}
          className={selectCls}
        >
          <option value="">All actions</option>
          <option value="blocked">Blocked</option>
          <option value="monitored">Monitored</option>
        </select>

        <input
          value={clientIP}
          onChange={(e) => resetToFirstPage(setClientIP)(e.target.value)}
          placeholder="Filter by IP…"
          className={`${selectCls} font-mono`}
        />
      </div>

      {error && <p className="text-sm text-signal-red">{error}</p>}

      <div className="overflow-hidden border border-border">
        <table className="w-full text-left text-sm">
          <thead>
            <tr className="border-b border-border bg-surface text-text-dim">
              <th className="px-4 py-3 font-medium">Time</th>
              <th className="px-4 py-3 font-medium">Site</th>
              <th className="px-4 py-3 font-medium">Category</th>
              <th className="px-4 py-3 font-medium">Action</th>
              <th className="px-4 py-3 font-medium">IP</th>
              <th className="px-4 py-3 font-medium">Request</th>
              <th className="px-4 py-3 font-medium">Score</th>
            </tr>
          </thead>
          <tbody>
            {logs.map((log) => (
              <tr
                key={log.id}
                onClick={() => setSelected(log)}
                className="cursor-pointer border-b border-border last:border-0 hover:bg-surface"
              >
                <td className="whitespace-nowrap px-4 py-3 font-mono text-xs text-text-dim">
                  {new Date(log.occurred_at).toLocaleString()}
                </td>
                <td className="px-4 py-3 text-text-dim">{log.site_name || "—"}</td>
                <td className="px-4 py-3">
                  <CategoryBadge category={log.category} />
                </td>
                <td className="px-4 py-3">
                  <ActionBadge action={log.action} />
                </td>
                <td className="px-4 py-3 font-mono text-text-dim">{log.client_ip}</td>
                <td className="max-w-xs truncate px-4 py-3 font-mono text-xs text-text-faint">
                  {log.method} {log.path}
                </td>
                <td className="px-4 py-3 font-mono text-text-dim">{log.score}</td>
              </tr>
            ))}
            {logs.length === 0 && (
              <tr>
                <td colSpan={7} className="px-4 py-10 text-center text-sm text-text-faint">
                  No attack log entries match these filters.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between text-sm text-text-dim">
        <span>
          {total.toLocaleString()} total entr{total === 1 ? "y" : "ies"}
        </span>
        <div className="flex items-center gap-2">
          <button
            disabled={page === 0}
            onClick={() => setPage((p) => Math.max(0, p - 1))}
            className="rounded p-1.5 hover:bg-surface-2 disabled:opacity-30"
            aria-label="Previous page"
          >
            <ChevronLeft className="h-4 w-4" />
          </button>
          <span>
            Page {page + 1} of {totalPages}
          </span>
          <button
            disabled={page + 1 >= totalPages}
            onClick={() => setPage((p) => p + 1)}
            className="rounded p-1.5 hover:bg-surface-2 disabled:opacity-30"
            aria-label="Next page"
          >
            <ChevronRight className="h-4 w-4" />
          </button>
        </div>
      </div>

      {selected && <LogDetail log={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}

function LogDetail({ log, onClose }: { log: AttackLog; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 px-4">
      <div className="w-full max-w-lg border border-border bg-surface-2 p-6">
        <div className="flex items-start justify-between">
          <h2 className="font-display text-base font-600 text-text">Request detail</h2>
          <button onClick={onClose} aria-label="Close" className="text-text-dim hover:text-text">
            <X className="h-5 w-5" />
          </button>
        </div>

        <dl className="mt-4 flex flex-col gap-3 text-sm">
          <Row label="Time" value={new Date(log.occurred_at).toLocaleString()} />
          <Row label="Site" value={log.site_name || "—"} />
          <Row label="Client IP" value={log.client_ip} mono />
          <Row label="Method & path" value={`${log.method} ${log.path}`} mono />
          <Row
            label="Category / action"
            value={
              <span className="flex gap-2">
                <CategoryBadge category={log.category} />
                <ActionBadge action={log.action} />
              </span>
            }
          />
          <Row label="Score" value={String(log.score)} />
          <Row label="Matched rules" value={(log.rule_ids ?? []).join(", ") || "—"} mono />
          <Row label="User-Agent" value={log.user_agent || "—"} mono />
          {log.snippet && (
            <div>
              <dt className="mb-1 text-text-dim">Matched content</dt>
              <dd className="break-all border border-border bg-surface px-3 py-2 font-mono text-xs text-text">
                {log.snippet}
              </dd>
            </div>
          )}
        </dl>
      </div>
    </div>
  );
}

function Row({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-4">
      <dt className="shrink-0 text-text-dim">{label}</dt>
      <dd className={`text-right text-text ${mono ? "break-all font-mono text-xs" : ""}`}>{value}</dd>
    </div>
  );
}

const selectCls =
  "rounded-md border border-border bg-surface px-3 py-1.5 text-sm text-text-dim outline-none focus:border-signal-red/60";
