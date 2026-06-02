import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "sentinel-brief",
  description: "Daily cyber-threat OSINT brief over an SBOM.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body className="min-h-screen">
        <header className="border-b border-zinc-800 px-6 py-4 flex items-center justify-between">
          <a href="/" className="font-semibold tracking-tight">
            sentinel-brief
          </a>
          <nav className="flex gap-4 text-sm text-zinc-400">
            <a href="/" className="hover:text-zinc-100">Watchlists</a>
            <a href="/runs" className="hover:text-zinc-100">Ingest runs</a>
          </nav>
        </header>
        <main className="px-6 py-6 max-w-5xl mx-auto">{children}</main>
      </body>
    </html>
  );
}
