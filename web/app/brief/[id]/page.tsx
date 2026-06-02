"use client";

import { use, useEffect, useState } from "react";
import { api, type BriefOut } from "../../../lib/api";

export default function BriefPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const [brief, setBrief] = useState<BriefOut | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api<BriefOut>(`/briefs/${id}`).then(setBrief).catch(e => setError(String(e.message ?? e)));
  }, [id]);

  if (error) return <p className="text-red-400 text-sm">{error}</p>;
  if (!brief) return <p className="text-zinc-500 text-sm">loading...</p>;

  return (
    <div>
      <h1 className="text-2xl font-semibold">{brief.title}</h1>
      <div className="text-xs text-zinc-500 mb-4">
        {new Date(brief.generated_at).toLocaleString()} · model {brief.model_id}
      </div>
      <pre className="whitespace-pre-wrap font-sans">{brief.summary_markdown}</pre>
      {brief.cited_urls.length > 0 && (
        <section className="mt-6">
          <h2 className="text-lg font-semibold">Citations</h2>
          <ul className="text-sm text-sky-400 list-disc list-inside">
            {brief.cited_urls.map(u => (
              <li key={u}><a href={u} target="_blank" rel="noopener noreferrer">{u}</a></li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}
