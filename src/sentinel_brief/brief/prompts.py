SYSTEM_PROMPT = """You are an analyst writing a daily cyber-threat brief.

You will be given a watchlist (the user's software stack) and a ranked list of \
matched advisories from the last 7 days, with scores and supporting metadata.

Your job:
1. Write a tight, useful daily brief (markdown). Do not pad. Do not editorialize.
2. Lead with the 1-3 highest-priority items the reader should act on today.
3. For every claim, cite the source URL inline as a markdown link.
4. Be specific: name the package, the affected versions, the fix version if known, \
and the EPSS / KEV / CVSS signal that justifies the rank.
5. If a finding is uncertain (loose match, missing version), say so — do not \
manufacture confidence.
6. Close with a one-line "What I'd do today" recommendation per top item. \
No filler.

Format:
# Daily Brief — {date} — {watchlist_name}

## Top priorities
(numbered list of 1-3 items, each with: package, advisory, severity, why-now, fix, citation)

## Other notable
(short bullets, only if material)

## Notes
(uncertainty, gaps, why a normally-loud thing was demoted)
"""


USER_PROMPT_TEMPLATE = """Watchlist: {watchlist_name}
Date: {date}

The following findings were matched against the watchlist over the last 7 days, \
sorted by score. Each finding lists: component, advisory, severity, score breakdown, \
and references.

{findings_block}

Write the brief now per the system instructions. Cite inline. Do not list \
findings I did not give you.
"""


def render_finding(idx: int, finding_payload: dict) -> str:
    f = finding_payload
    bd = f["score_breakdown"]
    refs = "\n".join(f"  - {r['url']}" + (f" ({r['kind']})" if r.get("kind") else "") for r in f["references"][:6])
    affected = ", ".join(
        f"{a['ecosystem']}/{a['package_name']}{(' fixed in ' + a['fixed']) if a.get('fixed') else ''}"
        for a in f["affected"][:3]
    )
    return (
        f"---\n"
        f"[{idx}] {f['component_purl']}  (score {f['score']:.3f}, matched_via {f['matched_via']})\n"
        f"  Advisory: {f['title']}  ({f['ids']})\n"
        f"  Severity: {f.get('severity') or '?'}  CVSS: {f.get('cvss_score') or '?'}  "
        f"KEV: {'YES' if f.get('kev') else 'no'}  EPSS: {f.get('epss_score') or '-'}\n"
        f"  Score breakdown: severity={bd['severity']}, match={bd['match_quality']}, "
        f"kev={bd['kev']}, epss={bd['epss']}, recency={bd['recency']}\n"
        f"  Affected: {affected or '-'}\n"
        f"  Summary: {(f.get('summary') or '').strip()[:600]}\n"
        f"  References:\n{refs or '  (none)'}\n"
    )
