// Typed client for the admin API. Every mutating request automatically
// attaches the CSRF token read from the (non-HttpOnly) _waf_csrf cookie,
// matching the double-submit pattern the backend expects; the session
// cookie itself is HttpOnly and travels automatically via
// credentials: "same-origin".

export interface SensitivePath {
  prefix: string;
  rps: number;
  burst: number;
}

export interface Site {
  id: string;
  name: string;
  domain: string;
  upstream_url: string;
  enabled: boolean;
  mode: "block" | "monitor";
  block_threshold: number;
  rate_limit_rps: number;
  rate_limit_burst: number;
  bot_challenge_enabled: boolean;
  bot_challenge_mode: "pow" | "turnstile";
  turnstile_site_key: string;
  pow_difficulty_bits: number;
  sensitive_paths: SensitivePath[];
  trusted_bot_allowlist: string[];
  created_at: string;
  updated_at: string;
}

export type SiteInput = Omit<
  Site,
  "id" | "created_at" | "updated_at" | "turnstile_site_key"
> & {
  turnstile_site_key: string;
  turnstile_secret_key: string;
};

export interface AttackLog {
  id: number;
  site_id: string;
  site_name?: string;
  occurred_at: string;
  client_ip: string;
  method: string;
  path: string;
  category: string;
  action: "blocked" | "monitored" | string;
  score: number;
  rule_ids: string[];
  user_agent: string;
  snippet: string;
}

export interface TimeseriesPoint {
  bucket: string;
  blocked: number;
  total: number;
}

export interface StatsSummary {
  total_requests: number;
  blocked_requests: number;
  challenged_count: number;
  rate_limited_count: number;
  by_category: Record<string, number>;
  timeseries: TimeseriesPoint[];
  top_ips: { ip: string; count: number }[];
  top_sites: { site_id: string; site_name: string; count: number }[];
}

export interface LogQuery {
  site_id?: string;
  category?: string;
  action?: string;
  client_ip?: string;
  limit?: number;
  offset?: number;
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = "ApiError";
  }
}

function getCookie(name: string): string {
  const match = document.cookie.match(
    new RegExp("(?:^|; )" + name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "=([^;]*)"),
  );
  return match ? decodeURIComponent(match[1]) : "";
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {};
  if (body !== undefined) headers["Content-Type"] = "application/json";
  if (method !== "GET" && method !== "HEAD") {
    const csrf = getCookie("_waf_csrf");
    if (csrf) headers["X-CSRF-Token"] = csrf;
  }

  const res = await fetch(path, {
    method,
    headers,
    credentials: "same-origin",
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

  if (!res.ok) {
    let message = res.statusText || `request failed (${res.status})`;
    try {
      const data = await res.json();
      if (data && typeof data.error === "string") message = data.error;
    } catch {
      // response body wasn't JSON; fall back to statusText
    }
    throw new ApiError(res.status, message);
  }

  if (res.status === 204) return undefined as T;
  const text = await res.text();
  return (text ? JSON.parse(text) : undefined) as T;
}

function toQueryString(params: Record<string, string | number | undefined>): string {
  const usp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== "") usp.set(k, String(v));
  }
  return usp.toString();
}

export const api = {
  login: (email: string, password: string) =>
    request<{ id: string; email: string }>("POST", "/api/auth/login", { email, password }),
  logout: () => request<{ ok: boolean }>("POST", "/api/auth/logout"),
  me: () => request<{ id: string; email: string }>("GET", "/api/auth/me"),
  changePassword: (current_password: string, new_password: string) =>
    request<{ ok: boolean }>("POST", "/api/auth/change-password", {
      current_password,
      new_password,
    }),

  listSites: () => request<Site[]>("GET", "/api/sites"),
  getSite: (id: string) => request<Site>("GET", `/api/sites/${id}`),
  createSite: (input: SiteInput) => request<Site>("POST", "/api/sites", input),
  updateSite: (id: string, input: SiteInput) => request<Site>("PUT", `/api/sites/${id}`, input),
  deleteSite: (id: string) => request<{ ok: boolean }>("DELETE", `/api/sites/${id}`),

  listLogs: (params: LogQuery) =>
    request<{ logs: AttackLog[]; total: number }>(
      "GET",
      `/api/logs?${toQueryString(params as Record<string, string | number | undefined>)}`,
    ),
  statsSummary: (hours: number) => request<StatsSummary>("GET", `/api/stats/summary?hours=${hours}`),
};
