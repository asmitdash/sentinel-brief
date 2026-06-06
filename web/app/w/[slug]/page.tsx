"use client";

import { useEffect, useState } from "react";
import {
  api,
  type BriefOut,
  type BriefSummary,
  type Finding,
} from "../../../lib/api";

export default function WatchlistPage({ params }: { params: { slug: string } }) {
  const { slug } = params;
  const [findings, setFindings] = useState<Finding[]>([]);
  const [briefs, setBriefs] = useState<BriefSummary[]>([]);
  const [busy, setBusy] = useState<string | null>(null);
  const [latest, setLatest] = useState<BriefOut | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function reload() {
    try {
      setFindings(await api<Finding[]>(`/watchlists/${slug}/findings?limit=50`));
      setBriefs(await api<BriefSummary[]>(`/watchlists/${slug}/briefs`));
    } catch (e: any) {
      setError(String(e.message ?? e));
    }
  }

  useEffect(() => { reload(); }, [slug]);

  async function runMatch() {
    setBusy("match");
    setError(null);
    try {
      await api(`/watchlists/${slug}/match`, { method: "POST" });
      await reload();
    } catch (e: any) {
      setError(String(e.message ?? e));
    } finally {
      setBusy(null);
    }
  }

  async function runIngest() {
    setBusy("ingest");
    setError(null);
    try {
      await api(`/ingest/run`, { method: "POST" });
      await reload();
    } catch (e: any) {
      setError(String(e.message ?? e));
    } finally {
      setBusy(null);
    }
  }

  async function generateBrief(dry: boolean = false) {
    setBusy("brief");
    setError(null);
    try {
      const b = await api<BriefOut>(
        `/watchlists/${slug}/briefs/generate?dry_run=${dry}`,
        { method: "POST" }
      );
      setLatest(b);
      await reload();
    } catch (e: any) {
      setError(String(e.message ?? e));
    } finally {
      setBusy(null);
    }
  }

  async function rate(briefId: number, n: number) {
    await api(`/feedback`, {
      method: "POST",
      body: JSON.stringify({ brief_id: briefId, rating: n }),
    });
    await reload();
  }

  return (
    <div className="space-y-8">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold">{slug}</h1>
        <div className="flex gap-2">
          <button onClick={runIngest} disabled={!!busy}
            className="bg-zinc-800 hover:bg-zinc-700 px-3 py-1.5 rounded text-sm">
            {busy === "ingest" ? "Ingesting..." : "Run ingest"}
          </button>
          <button onClick={runMatch} disabled={!!busy}
            className="bg-zinc-800 hover:bg-zinc-700 px-3 py-1.5 rounded text-sm">
            {busy === "match" ? "Matching..." : "Run match"}
          </button>
          <button onClick={() => generateBrief(true)} disabled={!!busy}
            className="bg-zinc-800 hover:bg-zinc-700 px-3 py-1.5 rounded text-sm">
            Dry-run brief
          </button>
          <button onClick={() => generateBrief(false)} disabled={!!busy}
            className="bg-sky-600 px-3 py-1.5 rounded text-sm">
            {busy === "brief" ? "Generating..." : "Generate brief"}
          </button>
        </div>
      </div>
      {error && <p className="text-red-400 text-sm">{error}</p>}

      {latest && (
        <section className="border border-sky-800 rounded p-4">
          <h2 className="text-lg font-semibold mb-1">{latest.title}</h2>
          <div className="text-xs text-zinc-500 mb-3">
            generated {new Date(latest.generated_at).toLocaleString()} ·
            model {latest.model_id} ·
            {latest.input_tokens ?? "?"} in / {latest.output_tokens ?? "?"} out
          </div>
          <BriefMarkdown md={latest.summary_markdown} />
          <div className="mt-3 flex gap-1 items-center">
            <span className="text-xs text-zinc-400">Rate this brief:</span>
            {[1, 2, 3, 4, 5].map(n => (
              <button key={n} onClick={() => rate(latest.id, n)}
                className="text-zinc-400 hover:text-yellow-400">
                {n <= (latest.user_rating ?? 0) ? "★" : "☆"}
              </button>
            ))}
          </div>
        </section>
      )}

      <section>
        <h2 className="text-lg font-semibold mb-2">Top findings</h2>
        {findings.length === 0 && (
          <p className="text-zinc-500 text-sm">no findings yet — run ingest, then match</p>
        )}
        <ul className="space-y-2">
          {findings.map(f => (
            <li key={f.id} className="border border-zinc-800 rounded p-3">
              <div className="flex justify-between items-baseline gap-3">
                <div>
                  <div className="font-medium">{f.title}</div>
                  <div className="text-xs text-zinc-500">
                    {f.component.ecosystem}/{f.component.name}
                    {f.component.version ? ` @ ${f.component.version}` : ""} ·{" "}
                    {[f.cve_id, f.ghsa_id].filter(Boolean).join(" / ")}
                  </div>
                </div>
                <div className="text-right">
                  <div className="text-sky-400 font-mono">{f.score.toFixed(3)}</div>
                  <div className="text-xs text-zinc-500">
                    {f.severity ?? "?"}{f.kev ? " · KEV" : ""}
                    {f.epss_score != null ? ` · EPSS ${f.epss_score.toFixed(3)}` : ""}
                  </div>
                </div>
              </div>
              <div className="mt-2 text-xs text-zinc-500">
                matched via {f.matched_via} · breakdown:{" "}
                {Object.entries(f.score_breakdown).map(([k, v]) => `${k}=${v}`).join("  ")}
              </div>
              {f.references.length > 0 && (
                <div className="mt-2 text-xs space-x-2">
                  {f.references.slice(0, 4).map((r, i) => (
                    <a key={i} href={r.url} target="_blank" rel="noopener noreferrer"
                      className="text-sky-400 hover:underline">
                      {r.kind || "ref"} ↗
                    </a>
                  ))}
                </div>
              )}
            </li>
          ))}
        </ul>
      </section>

      <section>
        <h2 className="text-lg font-semibold mb-2">Brief history</h2>
        {briefs.length === 0 && <p className="text-zinc-500 text-sm">none yet</p>}
        <ul className="divide-y divide-zinc-800 border border-zinc-800 rounded">
          {briefs.map(b => (
            <li key={b.id} className="px-3 py-2 flex justify-between items-center">
              <a href={`/brief/${b.id}`} className="hover:text-sky-400">{b.title}</a>
              <span className="text-xs text-zinc-500">
                {new Date(b.generated_at).toLocaleString()}
                {b.user_rating ? ` · ${"★".repeat(b.user_rating)}` : ""}
              </span>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}

function BriefMarkdown({ md }: { md: string }) {
  // Loaded lazily so server bundles stay slim
  const [Comp, setComp] = useState<any>(null);
  useEffect(() => {
    Promise.all([
      import("react-markdown"),
      import("remark-gfm"),
    ]).then(([rm, rg]) => {
      setComp(() => ({ children }: any) => {
        const M = rm.default;
        return <M remarkPlugins={[rg.default]}>{children}</M>;
      });
    });
  }, []);
  if (!Comp) return <pre className="whitespace-pre-wrap text-sm">{md}</pre>;
  return (
    <div className="prose-brief">
      <Comp>{md}</Comp>
    </div>
  );
}
