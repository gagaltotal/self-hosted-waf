import { useEffect, useState } from "react";
import { Plus, Pencil, Trash2 } from "lucide-react";
import { api, ApiError, type Site, type SiteInput } from "../api/client";
import { ModeBadge } from "../components/Badge";
import SiteDrawer from "../components/SiteDrawer";
import ConfirmDialog from "../components/ConfirmDialog";

export default function Sites() {
  const [sites, setSites] = useState<Site[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [drawerOpen, setDrawerOpen] = useState(false);
  const [editing, setEditing] = useState<Site | null>(null);
  const [saving, setSaving] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);

  const [pendingDelete, setPendingDelete] = useState<Site | null>(null);

  function load() {
    api
      .listSites()
      .then((res) => setSites(res ?? []))
      .catch(() => setError("Could not load sites."))
      .finally(() => setLoaded(true));
  }

  useEffect(load, []);

  function openAdd() {
    setEditing(null);
    setFormError(null);
    setDrawerOpen(true);
  }
  function openEdit(site: Site) {
    setEditing(site);
    setFormError(null);
    setDrawerOpen(true);
  }

  async function handleSave(input: SiteInput) {
    setSaving(true);
    setFormError(null);
    try {
      if (editing) {
        await api.updateSite(editing.id, input);
      } else {
        await api.createSite(input);
      }
      setDrawerOpen(false);
      load();
    } catch (e) {
      setFormError(e instanceof ApiError ? e.message : "Could not save site.");
    } finally {
      setSaving(false);
    }
  }

  async function handleDelete() {
    if (!pendingDelete) return;
    try {
      await api.deleteSite(pendingDelete.id);
      setPendingDelete(null);
      load();
    } catch {
      setError("Could not delete site.");
      setPendingDelete(null);
    }
  }

  return (
    <div className="flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <h1 className="font-display text-2xl font-600 text-text">Sites</h1>
        <button
          onClick={openAdd}
          className="flex items-center gap-1.5 rounded-md bg-signal-red px-3 py-1.5 text-sm font-medium text-white hover:bg-[#e14a4a]"
        >
          <Plus className="h-4 w-4" /> Add site
        </button>
      </div>

      {error && <p className="text-sm text-signal-red">{error}</p>}

      {sites.length === 0 && loaded && (
        <div className="border border-dashed border-border px-6 py-14 text-center">
          <p className="text-sm text-text-dim">No sites protected yet.</p>
          <button
            onClick={openAdd}
            className="mt-3 text-sm font-medium text-signal-red hover:underline"
          >
            Add your first site
          </button>
        </div>
      )}

      {sites.length > 0 && (
        <div className="overflow-hidden border border-border">
          <table className="w-full text-left text-sm">
            <thead>
              <tr className="border-b border-border bg-surface text-text-dim">
                <th className="px-4 py-3 font-medium">Name</th>
                <th className="px-4 py-3 font-medium">Domain</th>
                <th className="px-4 py-3 font-medium">Upstream</th>
                <th className="px-4 py-3 font-medium">Mode</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3" />
              </tr>
            </thead>
            <tbody>
              {sites.map((site) => (
                <tr key={site.id} className="border-b border-border last:border-0 hover:bg-surface">
                  <td className="px-4 py-3 text-text">{site.name}</td>
                  <td className="px-4 py-3 font-mono text-text-dim">{site.domain}</td>
                  <td className="px-4 py-3 font-mono text-text-faint">{site.upstream_url}</td>
                  <td className="px-4 py-3">
                    <ModeBadge mode={site.mode} />
                  </td>
                  <td className="px-4 py-3">
                    {site.enabled ? (
                      <span className="text-signal-teal">Active</span>
                    ) : (
                      <span className="text-text-faint">Disabled</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex justify-end gap-1">
                      <button
                        onClick={() => openEdit(site)}
                        aria-label={`Edit ${site.name}`}
                        className="rounded p-1.5 text-text-dim hover:bg-surface-2 hover:text-text"
                      >
                        <Pencil className="h-4 w-4" />
                      </button>
                      <button
                        onClick={() => setPendingDelete(site)}
                        aria-label={`Delete ${site.name}`}
                        className="rounded p-1.5 text-text-dim hover:bg-surface-2 hover:text-signal-red"
                      >
                        <Trash2 className="h-4 w-4" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <SiteDrawer
        open={drawerOpen}
        site={editing}
        onClose={() => setDrawerOpen(false)}
        onSave={handleSave}
        saving={saving}
        error={formError}
      />

      <ConfirmDialog
        open={pendingDelete !== null}
        title={`Delete ${pendingDelete?.name}?`}
        description="Traffic to this domain will no longer be inspected or protected. This cannot be undone."
        confirmLabel="Delete site"
        danger
        onConfirm={handleDelete}
        onCancel={() => setPendingDelete(null)}
      />
    </div>
  );
}
