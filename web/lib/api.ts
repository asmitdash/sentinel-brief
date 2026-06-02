const BASE = process.env.NEXT_PUBLIC_API_BASE || "http://localhost:8000";

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(init?.headers || {}),
    },
    cache: "no-store",
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`${res.status} ${res.statusText}: ${text}`);
  }
  return res.json() as Promise<T>;
}

export async function uploadSbom(slug: string, name: string, file: File) {
  const fd = new FormData();
  fd.set("slug", slug);
  fd.set("name", name);
  fd.set("sbom", file);
  const res = await fetch(`${BASE}/watchlists/upload`, { method: "POST", body: fd });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

export type Watchlist = { id: number; slug: string; name: string; component_count: number };
export type BriefSummary = {
  id: number;
  watchlist_id: number;
  generated_at: string;
  title: string;
  user_rating: number | null;
};
export type BriefOut = BriefSummary & {
  summary_markdown: string;
  finding_ids: number[];
  cited_urls: string[];
  model_id: string;
  input_tokens: number | null;
  output_tokens: number | null;
};
export type Finding = {
  id: number;
  component: { ecosystem: string; name: string; version: string | null; purl: string };
  cve_id: string | null;
  ghsa_id: string | null;
  title: string;
  severity: string | null;
  cvss_score: number | null;
  kev: boolean;
  epss_score: number | null;
  score: number;
  matched_via: string;
  score_breakdown: Record<string, number>;
  references: { url: string; kind: string | null }[];
};
export type IngestRun = {
  id: number;
  source_slug: string;
  started_at: string;
  finished_at: string | null;
  status: string;
  items_seen: number;
  items_upserted: number;
  error: string | null;
};
