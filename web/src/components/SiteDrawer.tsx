import { useEffect, useState } from "react";
import { X, Plus, Trash2 } from "lucide-react";
import type { Site, SiteInput, SensitivePath } from "../api/client";

const emptySite: SiteInput = {
  name: "",
  domain: "",
  upstream_url: "",
  enabled: true,
  mode: "block",
  block_threshold: 7,
  rate_limit_rps: 10,
  rate_limit_burst: 20,
  bot_challenge_enabled: true,
  bot_challenge_mode: "pow",
  turnstile_site_key: "",
  turnstile_secret_key: "",
  pow_difficulty_bits: 16,
  sensitive_paths: [],
  trusted_bot_allowlist: [],
};

export default function SiteDrawer({
  open,
  site,
  onClose,
  onSave,
  saving,
  error,
}: {
  open: boolean;
  site: Site | null;
  onClose: () => void;
  onSave: (input: SiteInput) => void;
  saving: boolean;
  error: string | null;
}) {
  const [form, setForm] = useState<SiteInput>(emptySite);
  const [allowlistText, setAllowlistText] = useState("");

  useEffect(() => {
    if (site) {
      setForm({ ...site, turnstile_secret_key: "" });
      setAllowlistText(site.trusted_bot_allowlist.join("\n"));
    } else {
      setForm(emptySite);
      setAllowlistText("");
    }
  }, [site, open]);

  if (!open) return null;

  function update<K extends keyof SiteInput>(key: K, value: SiteInput[K]) {
    setForm((f) => ({ ...f, [key]: value }));
  }

  function addSensitivePath() {
    update("sensitive_paths", [...form.sensitive_paths, { prefix: "/login", rps: 2, burst: 5 }]);
  }
  function updateSensitivePath(idx: number, patch: Partial<SensitivePath>) {
    const next = form.sensitive_paths.map((p, i) => (i === idx ? { ...p, ...patch } : p));
    update("sensitive_paths", next);
  }
  function removeSensitivePath(idx: number) {
    update(
      "sensitive_paths",
      form.sensitive_paths.filter((_, i) => i !== idx),
    );
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    const allowlist = allowlistText
      .split("\n")
      .map((s) => s.trim())
      .filter(Boolean);
    onSave({ ...form, trusted_bot_allowlist: allowlist });
  }

  return (
    <div className="fixed inset-0 z-50 flex justify-end bg-black/60">
      <div className="flex h-full w-full max-w-xl flex-col overflow-y-auto border-l border-border bg-surface">
        <div className="flex items-center justify-between border-b border-border px-6 py-4">
          <h2 className="font-display text-lg font-600 text-text">
            {site ? "Edit site" : "Add site"}
          </h2>
          <button
            onClick={onClose}
            aria-label="Close"
            className="rounded p-1 text-text-dim hover:bg-surface-2 hover:text-text"
          >
            <X className="h-5 w-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="flex flex-1 flex-col gap-6 px-6 py-6">
          <section className="flex flex-col gap-4">
            <Field label="Name">
              <input
                required
                value={form.name}
                onChange={(e) => update("name", e.target.value)}
                placeholder="My website"
                className={inputCls}
              />
            </Field>
            <Field label="Domain" hint="The public hostname visitors use to reach this site.">
              <input
                required
                value={form.domain}
                onChange={(e) => update("domain", e.target.value)}
                placeholder="example.com"
                className={`${inputCls} font-mono`}
              />
            </Field>
            <Field label="Upstream URL" hint="Where the WAF forwards clean traffic -- your actual application server.">
              <input
                required
                value={form.upstream_url}
                onChange={(e) => update("upstream_url", e.target.value)}
                placeholder="http://app:3000"
                className={`${inputCls} font-mono`}
              />
            </Field>
            <label className="flex items-center gap-2 text-sm text-text">
              <input
                type="checkbox"
                checked={form.enabled}
                onChange={(e) => update("enabled", e.target.checked)}
                className={checkboxCls}
              />
              Site enabled
            </label>
          </section>

          <Divider label="Protection" />

          <section className="flex flex-col gap-4">
            <Field label="Mode" hint="Monitoring only logs suspicious requests without blocking them -- useful while tuning a new site.">
              <select
                value={form.mode}
                onChange={(e) => update("mode", e.target.value as SiteInput["mode"])}
                className={inputCls}
              >
                <option value="block">Block</option>
                <option value="monitor">Monitor only</option>
              </select>
            </Field>
            <Field label="Block threshold" hint="Requests scoring at or above this are blocked. Lower is stricter.">
              <input
                type="number"
                min={1}
                value={form.block_threshold}
                onChange={(e) => update("block_threshold", Number(e.target.value))}
                className={inputCls}
              />
            </Field>
            <div className="grid grid-cols-2 gap-4">
              <Field label="Rate limit (requests/sec)">
                <input
                  type="number"
                  min={1}
                  value={form.rate_limit_rps}
                  onChange={(e) => update("rate_limit_rps", Number(e.target.value))}
                  className={inputCls}
                />
              </Field>
              <Field label="Burst allowance">
                <input
                  type="number"
                  min={1}
                  value={form.rate_limit_burst}
                  onChange={(e) => update("rate_limit_burst", Number(e.target.value))}
                  className={inputCls}
                />
              </Field>
            </div>
          </section>

          <Divider label="Sensitive paths" />
          <section className="flex flex-col gap-3">
            <p className="text-xs text-text-dim">
              Apply a tighter rate limit to specific paths, such as a login form, to blunt
              brute-force attempts without throttling the rest of the site.
            </p>
            {form.sensitive_paths.map((p, i) => (
              <div key={i} className="flex items-center gap-2">
                <input
                  value={p.prefix}
                  onChange={(e) => updateSensitivePath(i, { prefix: e.target.value })}
                  placeholder="/login"
                  className={`${inputCls} flex-1 font-mono`}
                />
                <input
                  type="number"
                  min={1}
                  value={p.rps}
                  onChange={(e) => updateSensitivePath(i, { rps: Number(e.target.value) })}
                  className={`${inputCls} w-20`}
                  aria-label="Requests per second"
                />
                <input
                  type="number"
                  min={1}
                  value={p.burst}
                  onChange={(e) => updateSensitivePath(i, { burst: Number(e.target.value) })}
                  className={`${inputCls} w-20`}
                  aria-label="Burst"
                />
                <button
                  type="button"
                  onClick={() => removeSensitivePath(i)}
                  aria-label="Remove path"
                  className="rounded p-1.5 text-text-dim hover:bg-surface-2 hover:text-signal-red"
                >
                  <Trash2 className="h-4 w-4" />
                </button>
              </div>
            ))}
            <button
              type="button"
              onClick={addSensitivePath}
              className="flex w-fit items-center gap-1.5 text-sm text-text-dim hover:text-text"
            >
              <Plus className="h-4 w-4" /> Add path
            </button>
          </section>

          <Divider label="Bot defense" />
          <section className="flex flex-col gap-4">
            <label className="flex items-center gap-2 text-sm text-text">
              <input
                type="checkbox"
                checked={form.bot_challenge_enabled}
                onChange={(e) => update("bot_challenge_enabled", e.target.checked)}
                className={checkboxCls}
              />
              Challenge suspicious visitors before serving pages
            </label>

            {form.bot_challenge_enabled && (
              <>
                <Field label="Challenge type">
                  <select
                    value={form.bot_challenge_mode}
                    onChange={(e) =>
                      update("bot_challenge_mode", e.target.value as SiteInput["bot_challenge_mode"])
                    }
                    className={inputCls}
                  >
                    <option value="pow">Proof-of-work (built in, no account needed)</option>
                    <option value="turnstile">Cloudflare Turnstile</option>
                  </select>
                </Field>

                {form.bot_challenge_mode === "pow" ? (
                  <Field
                    label={`Difficulty: ${form.pow_difficulty_bits} bits`}
                    hint="Higher is a stronger deterrent but takes visitors' browsers longer to solve."
                  >
                    <input
                      type="range"
                      min={10}
                      max={22}
                      value={form.pow_difficulty_bits}
                      onChange={(e) => update("pow_difficulty_bits", Number(e.target.value))}
                      className="w-full accent-signal-red"
                    />
                  </Field>
                ) : (
                  <>
                    <Field label="Turnstile site key">
                      <input
                        value={form.turnstile_site_key}
                        onChange={(e) => update("turnstile_site_key", e.target.value)}
                        className={`${inputCls} font-mono`}
                      />
                    </Field>
                    <Field
                      label="Turnstile secret key"
                      hint={site ? "Leave blank to keep the current secret." : undefined}
                    >
                      <input
                        type="password"
                        value={form.turnstile_secret_key}
                        onChange={(e) => update("turnstile_secret_key", e.target.value)}
                        className={`${inputCls} font-mono`}
                        autoComplete="off"
                      />
                    </Field>
                  </>
                )}

                <Field
                  label="Trusted bots allowlist"
                  hint="One entry per line: a user-agent substring (e.g. Googlebot) or an IP/CIDR. These skip the challenge but are still subject to WAF rules and rate limits."
                >
                  <textarea
                    value={allowlistText}
                    onChange={(e) => setAllowlistText(e.target.value)}
                    rows={3}
                    placeholder={"Googlebot\n203.0.113.0/24"}
                    className={`${inputCls} font-mono`}
                  />
                </Field>
              </>
            )}
          </section>

          {error && (
            <p className="border border-signal-red/40 bg-signal-red-dim px-3 py-2 text-sm text-signal-red">
              {error}
            </p>
          )}

          <div className="mt-auto flex justify-end gap-3 border-t border-border pt-5">
            <button
              type="button"
              onClick={onClose}
              className="rounded-md px-4 py-2 text-sm text-text-dim hover:bg-surface-2 hover:text-text"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving}
              className="rounded-md bg-signal-red px-4 py-2 text-sm font-medium text-white hover:bg-[#e14a4a] disabled:opacity-60"
            >
              {saving ? "Saving…" : site ? "Save changes" : "Add site"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

function Field({
  label,
  hint,
  children,
}: {
  label: string;
  hint?: string;
  children: React.ReactNode;
}) {
  return (
    <label className="flex flex-col gap-1.5">
      <span className="text-sm text-text">{label}</span>
      {children}
      {hint && <span className="text-xs text-text-faint">{hint}</span>}
    </label>
  );
}

function Divider({ label }: { label: string }) {
  return (
    <div className="flex items-center gap-3">
      <span className="text-xs font-medium text-text-dim">{label}</span>
      <div className="h-px flex-1 bg-border" />
    </div>
  );
}

const inputCls =
  "w-full rounded-md border border-border bg-surface-2 px-3 py-2 text-sm text-text outline-none focus:border-signal-red/60";
const checkboxCls = "h-4 w-4 rounded border-border bg-surface-2 accent-signal-red";
