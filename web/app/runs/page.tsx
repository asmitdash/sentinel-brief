"use client";

import { useEffect, useState } from "react";
import { api, type IngestRun } from "../../lib/api";

export default function RunsPage() {
  const [runs, setRuns] = useState<IngestRun[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api<IngestRun[]>("/ingest/runs").then(setRuns).catch(e => setError(String(e.message ?? e)));
  }, []);

  return (
    <div>
      <h1 className="text-2xl font-semibold mb-4">Ingest runs</h1>
      {error && <p className="text-red-400 text-sm">{error}</p>}
      <table className="w-full text-sm border border-zinc-800">
        <thead className="bg-zinc-900 text-zinc-400">
          <tr>
            <th className="text-left p-2">started</th>
            <th className="text-left p-2">source</th>
            <th className="text-left p-2">status</th>
            <th className="text-right p-2">seen</th>
            <th className="text-right p-2">upserted</th>
            <th className="text-left p-2">error</th>
          </tr>
        </thead>
        <tbody>
          {runs.map(r => (
            <tr key={r.id} className="border-t border-zinc-800">
              <td className="p-2 text-zinc-500">{new Date(r.started_at).toLocaleString()}</td>
              <td className="p-2">{r.source_slug}</td>
              <td className={`p-2 ${r.status === "ok" ? "text-emerald-400" : "text-red-400"}`}>{r.status}</td>
              <td className="p-2 text-right font-mono">{r.items_seen}</td>
              <td className="p-2 text-right font-mono">{r.items_upserted}</td>
              <td className="p-2 text-zinc-500 truncate max-w-[40ch]">{r.error}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
