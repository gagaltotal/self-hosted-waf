const categoryStyle: Record<string, string> = {
  sqli: "bg-signal-red-dim text-signal-red",
  xss: "bg-signal-amber-dim text-signal-amber",
  cmdi: "bg-signal-violet-dim text-signal-violet",
  path_traversal: "bg-signal-teal-dim text-signal-teal",
  rate_limit: "bg-surface-2 text-text-dim",
  bot: "bg-signal-violet-dim text-signal-violet",
  other: "bg-surface-2 text-text-dim",
};

const categoryLabel: Record<string, string> = {
  sqli: "SQL injection",
  xss: "XSS",
  cmdi: "Command injection",
  path_traversal: "Path traversal",
  rate_limit: "Rate limit",
  bot: "Bot",
  other: "Other",
};

export function CategoryBadge({ category }: { category: string }) {
  const cls = categoryStyle[category] ?? categoryStyle.other;
  const label = categoryLabel[category] ?? category;
  return (
    <span className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ${cls}`}>
      {label}
    </span>
  );
}

const actionStyle: Record<string, string> = {
  blocked: "bg-signal-red-dim text-signal-red",
  monitored: "bg-signal-amber-dim text-signal-amber",
  challenged: "bg-signal-teal-dim text-signal-teal",
};

export function ActionBadge({ action }: { action: string }) {
  const cls = actionStyle[action] ?? "bg-surface-2 text-text-dim";
  return (
    <span className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-medium capitalize ${cls}`}>
      {action}
    </span>
  );
}

export function ModeBadge({ mode }: { mode: string }) {
  return mode === "block" ? (
    <span className="inline-flex items-center rounded px-2 py-0.5 text-xs font-medium bg-signal-red-dim text-signal-red">
      Blocking
    </span>
  ) : (
    <span className="inline-flex items-center rounded px-2 py-0.5 text-xs font-medium bg-signal-amber-dim text-signal-amber">
      Monitoring only
    </span>
  );
}
