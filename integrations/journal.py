"""
kx -- Hunt Journal Integration
Appends a structured finding summary to hunt_journal.md
"""

from datetime import datetime
from pathlib import Path
from extractor import Finding

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def append_to_journal(
    target: str,
    findings: list[Finding],
    journal_path: Path | str,
    diff: dict | None = None,
):
    journal_path = Path(journal_path)
    journal_path.parent.mkdir(parents=True, exist_ok=True)

    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    high_sev = [f for f in findings if SEVERITY_RANK.get(f.severity, 0) >= 3]

    lines = [
        f"\n---\n",
        f"## [{now}] kx -- {target}",
        f"",
        f"**JS files scanned:** N/A  |  **Total findings:** {len(findings)}  |  "
        f"**High/Critical:** {len(high_sev)}",
        f"",
    ]

    if diff and not diff.get("is_first_scan"):
        new_count = len(diff.get("new_findings", []))
        new_js = len(diff.get("new_js_files", []))
        lines.append(f"**Diff:** {new_count} new finding(s), {new_js} new JS file(s)\n")

    if high_sev:
        lines.append("### High/Critical Findings\n")
        lines.append("| Severity | Name | Match | Source |")
        lines.append("|----------|------|-------|--------|")
        for f in high_sev[:20]:
            match_safe = f.match[:60].replace("|", "\\|")
            lines.append(f"| {f.severity.upper()} | {f.name} | `{match_safe}` | {f.source_url} |")
        lines.append("")

    lines.append(f"*Full output: `kx_{target.replace('https://','').replace('/','_')}.json`*\n")

    with open(journal_path, "a") as jf:
        jf.write("\n".join(lines))
