"use client";

import { useEffect, useState } from "react";
import { api, uploadSbom, type Watchlist } from "../lib/api";

export default function Home() {
  const [watchlists, setWatchlists] = useState<Watchlist[]>([]);
  const [slug, setSlug] = useState("default");
  const [name, setName] = useState("Default Watchlist");
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function reload() {
    try {
      setWatchlists(await api<Watchlist[]>("/watchlists"));
    } catch (e: any) {
      setError(String(e.message ?? e));
    }
  }

  useEffect(() => { reload(); }, []);

  async function onUpload(e: React.FormEvent) {
    e.preventDefault();
    if (!file) return;
    setBusy(true);
    setError(null);
    try {
      await uploadSbom(slug, name, file);
      await reload();
    } catch (e: any) {
      setError(String(e.message ?? e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-8">
      <section>
        <h1 className="text-2xl font-semibold mb-2">Watchlists</h1>
        <p className="text-zinc-400 text-sm mb-4">
          Upload a <code>requirements.txt</code>, <code>package.json</code>, or CycloneDX SBOM
          to start tracking. Each upload registers a <em>watchlist</em> against ingested advisories.
        </p>
        <form onSubmit={onUpload} className="flex flex-wrap gap-3 items-end p-4 border border-zinc-800 rounded">
          <div className="flex flex-col">
            <label className="text-xs text-zinc-400">Slug</label>
            <input value={slug} onChange={e => setSlug(e.target.value)}
              className="bg-zinc-900 border border-zinc-800 rounded px-2 py-1 w-48" />
          </div>
          <div className="flex flex-col">
            <label className="text-xs text-zinc-400">Name</label>
            <input value={name} onChange={e => setName(e.target.value)}
              className="bg-zinc-900 border border-zinc-800 rounded px-2 py-1 w-72" />
          </div>
          <div className="flex flex-col">
            <label className="text-xs text-zinc-400">SBOM file</label>
            <input type="file" onChange={e => setFile(e.target.files?.[0] ?? null)}
              className="text-sm" />
          </div>
          <button type="submit" disabled={busy || !file}
            className="bg-sky-600 disabled:bg-zinc-700 text-white px-3 py-1.5 rounded">
            {busy ? "Uploading..." : "Upload"}
          </button>
        </form>
        {error && <p className="text-red-400 text-sm mt-2">{error}</p>}
      </section>

      <section>
        <h2 className="text-lg font-semibold mb-2">Existing</h2>
        {watchlists.length === 0 && <p className="text-zinc-500 text-sm">none yet</p>}
        <ul className="divide-y divide-zinc-800 border border-zinc-800 rounded">
          {watchlists.map(w => (
            <li key={w.id} className="px-3 py-2 flex justify-between items-center">
              <a href={`/w/${w.slug}`} className="hover:text-sky-400">
                <span className="font-medium">{w.name}</span>
                <span className="text-zinc-500 text-sm ml-2">({w.slug})</span>
              </a>
              <span className="text-xs text-zinc-500">{w.component_count} components</span>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
