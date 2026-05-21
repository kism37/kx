"""
kx -- Per-file Markdown reports

For each JS file scanned, write a `reports/<host>/<filename>.md` containing:
  - File summary (what kind of file is this -- entry bundle, lazy chunk,
    recovered source, plain script)
  - Form schemas defined in the file (with field counts and refine rules)
  - Mutations and what they send
  - Network calls (URL + body keys)
  - Tainted variables of interest
  - All findings inline, sorted by severity, with their evidence

The goal is hunter-readable notes that let you triage a file without
re-reading the bundle. Each report is self-contained.

Usage from kx.py:
    from file_reports import write_per_file_reports
    write_per_file_reports(target, all_findings, classifier.SUMMARIES,
                           out_dir=Path("reports"))
"""

from __future__ import annotations
import re
from pathlib import Path
from collections import defaultdict
from urllib.parse import urlparse

from extractor import Finding


def _safe_filename(s: str) -> str:
    """Make a string safe to use as a filename."""
    s = re.sub(r"[^\w.\-]+", "_", s)
    return s[:120] or "file"


def _filename_for(url: str) -> str:
    """Derive a stable .md filename for a JS URL."""
    if url.startswith("sourcemap://"):
        # sourcemap://<map-url>#<path>  →  use the original path
        path = url.split("#", 1)[1] if "#" in url else url
        return _safe_filename(path.lstrip("./")) + ".md"
    p = urlparse(url)
    # Use the path's last 2 segments to disambiguate similarly-named files
    segs = [s for s in p.path.split("/") if s][-2:] or ["root"]
    return _safe_filename("__".join(segs)) + ".md"


def _host_dir(url: str) -> str:
    if url.startswith("sourcemap://"):
        # sourcemap://<map-url>#... -- extract host from map URL
        rest = url[len("sourcemap://"):].split("#", 1)[0]
        try:
            return urlparse(rest).netloc or "recovered"
        except Exception:
            return "recovered"
    return urlparse(url).netloc or "unknown"


def _classify_file(url: str, summary: dict | None) -> str:
    """Short tag describing what kind of file this is."""
    if url.startswith("sourcemap://"):
        return "Source-map recovered"
    if not summary:
        return "Plain script"
    has_forms = bool(summary.get("forms"))
    has_mutations = bool(summary.get("mutations"))
    has_schemas = bool(summary.get("schemas"))
    if has_forms and has_mutations:
        return "Form + Mutation handler"
    if has_mutations:
        return "Mutation handler"
    if has_schemas:
        return "Schema/data module"
    if summary.get("networkCalls"):
        return "Network-call module"
    return "Misc / library code"


def _format_summary_block(summary: dict) -> list[str]:
    """Render the model summary as Markdown lines."""
    if not summary:
        return ["_No semantic model captured for this file._"]
    out = []

    schemas = summary.get("schemas", [])
    if schemas:
        out.append("### Form schemas")
        out.append("")
        for s in schemas:
            top = ", ".join(s.get("topFields", [])) or "(none)"
            out.append(
                f"- **`{s['name']}`** (line {s['line']}, {s['fieldCount']} field(s))"
            )
            out.append(f"  - Top-level fields: `{top}`")
            for r in s.get("refines", []) or []:
                msg = (r.get("message") or "(no message)").strip()
                out.append(
                    f"  - **`.refine()`** on `{r.get('path') or '?'}`: _{msg}_"
                )
        out.append("")

    forms = summary.get("forms", [])
    if forms:
        out.append("### Forms")
        out.append("")
        for f in forms:
            schema = f.get("resolverSchema") or "(none)"
            destruct = ", ".join(f.get("destructured", [])) or "(none)"
            out.append(
                f"- Form (line {f['line']}) -- schema: `{schema}`, destructured: `{destruct}`"
            )
        out.append("")

    mutations = summary.get("mutations", [])
    if mutations:
        out.append("### Mutations")
        out.append("")
        for m in mutations:
            out.append(
                f"- `{m['varName']}` "
                f"(hook category: `{m['hookCategory']}`, line {m['line']})"
            )
            for p in m.get("payloads", []) or []:
                spreads = ", ".join(p.get("spreads", [])) or "--"
                keys = ", ".join(p.get("keys", [])) or "--"
                out.append(f"  - Payload (line {p['line']})")
                out.append(f"    - Explicit keys: `{keys}`")
                out.append(f"    - Spreads: `{spreads}`")
                for fr in p.get("fieldsResolved", []) or []:
                    if fr["key"] == "...":
                        continue
                    out.append(
                        f"    - `{fr['key']}` ← _{fr['originType']}_"
                        f"{(': `' + fr['originName'] + '`') if fr.get('originName') else ''}"
                    )
        out.append("")

    netcalls = summary.get("networkCalls", [])
    if netcalls:
        out.append("### Network calls")
        out.append("")
        for n in netcalls:
            url = n.get("urlString") or "_(dynamic URL)_"
            keys = ", ".join(n.get("bodyKeys", [])) or "_(no body keys)_"
            out.append(f"- `{n['kind']}` → `{url}` (line {n['line']})")
            out.append(f"  - body keys: `{keys}`")
        out.append("")

    sessions = summary.get("sessionRefs", [])
    if sessions:
        names = ", ".join(s["varName"] for s in sessions)
        out.append(f"### Session refs\n\n- `{names}`\n")

    tainted = summary.get("taintedVars", [])
    if tainted:
        out.append(f"### Tainted variables\n")
        out.append(f"_Reach a sink only when crossed with a sink detector._\n")
        out.append(", ".join(f"`{t}`" for t in tainted) + "\n")

    sinks = summary.get("sinks", [])
    if sinks:
        out.append("### Sinks present")
        out.append("")
        for s in sinks:
            out.append(f"- `{s['name']}` (line {s['line']}, kind: {s['kind']})")
        out.append("")

    return out


def _format_findings_block(findings: list[Finding]) -> list[str]:
    if not findings:
        return ["_No findings._"]
    out = []
    # Group by severity, critical first
    sev_order = ["critical", "high", "medium", "low", "info"]
    by_sev: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_sev[f.severity].append(f)
    for sev in sev_order:
        if not by_sev.get(sev):
            continue
        out.append(f"### {sev.upper()}")
        out.append("")
        for f in by_sev[sev]:
            out.append(f"#### {f.name}")
            out.append("")
            out.append(f"- **Target:** `{f.match}`")
            out.append(f"- **Line:** {f.line}")
            out.append(f"- **Confidence:** {f.confidence}")
            if f.note:
                out.append("")
                out.append(f.note)
            if f.evidence:
                out.append("")
                out.append("**Evidence:**")
                out.append("")
                for ev in f.evidence:
                    kind = ev.get("kind", "?")
                    line = ev.get("line", "")
                    snip = (ev.get("snippet") or "").replace("\n", " ")
                    if len(snip) > 280:
                        snip = snip[:280] + "..."
                    out.append(f"- `{kind}` (line {line}): `{snip}`")
            out.append("")
    return out


def write_per_file_reports(
    target: str,
    findings: list[Finding],
    summaries: dict[str, dict],
    out_dir: Path,
    *,
    only_with_findings: bool = True,
) -> dict:
    """
    Write one Markdown report per scanned JS file.

    Returns: {written: int, paths: [Path...]}
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Group findings by their source URL
    findings_by_url: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        findings_by_url[f.source_url].append(f)

    # Set of URLs to potentially report on -- union of summaries + findings
    urls = set(summaries.keys()) | set(findings_by_url.keys())

    written_paths: list[Path] = []

    for url in sorted(urls):
        file_findings = findings_by_url.get(url, [])
        summary = summaries.get(url)

        if only_with_findings and not file_findings and not summary:
            continue
        # If we only want files that have either findings OR a semantic
        # surface (schemas/forms/mutations), skip empty utility scripts.
        if only_with_findings and not file_findings and summary:
            if not (summary.get("schemas") or summary.get("forms")
                    or summary.get("mutations") or summary.get("networkCalls")
                    or summary.get("sinks")):
                continue

        host = _host_dir(url)
        fname = _filename_for(url)
        host_dir = out_dir / host
        host_dir.mkdir(parents=True, exist_ok=True)
        path = host_dir / fname

        kind = _classify_file(url, summary)
        sev_counts = defaultdict(int)
        for f in file_findings:
            sev_counts[f.severity] += 1
        sev_summary = " · ".join(
            f"{k}: {sev_counts[k]}"
            for k in ("critical","high","medium","low","info")
            if sev_counts[k]
        ) or "no findings"

        lines = [
            f"# {fname.rsplit('.md',1)[0]}",
            "",
            f"- **URL:** {url}",
            f"- **Target:** {target}",
            f"- **Kind:** {kind}",
            f"- **Findings:** {sev_summary}",
            "",
            "## Semantic summary",
            "",
            *_format_summary_block(summary or {}),
            "",
            "## Findings",
            "",
            *_format_findings_block(file_findings),
        ]
        path.write_text("\n".join(lines))
        written_paths.append(path)

    return {"written": len(written_paths), "paths": written_paths}
