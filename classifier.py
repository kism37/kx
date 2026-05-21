"""
kx -- Classifier + AST orchestrator
Invokes the Node.js AST worker and merges findings with static extractor output.
Also applies confidence scoring and deduplication across both sources.
"""

import asyncio
import json
import subprocess
import shutil
from pathlib import Path
from typing import Any

from extractor import Finding, SEVERITY_RANK

AST_WORKER = Path(__file__).parent / "ast_worker" / "analyze.js"
NODE_BIN = shutil.which("node") or "node"

SEVERITY_SCORE = {"critical": 100, "high": 75, "medium": 40, "low": 10, "info": 0}


def _ast_severity_map(sev: str) -> str:
    """Map AST worker severity strings to our standard tiers."""
    return {
        "critical": "critical",
        "high":     "high",
        "medium":   "medium",
        "low":      "low",
        "info":     "low",
    }.get(sev, "low")


# Per-file semantic summaries captured during run_ast (keyed by source_url).
# Lives at module scope so other modules (file_reports.py) can consult it.
SUMMARIES: dict[str, dict] = {}


async def run_ast(source_url: str, js_content: str) -> list[Finding]:
    """
    Run the Node.js AST worker on js_content.
    Returns findings in the same Finding dataclass format.

    Also stashes the per-file semantic summary in `classifier.SUMMARIES`
    keyed by source_url, so report generators can later render per-file
    Markdown notes.
    """
    if not AST_WORKER.exists():
        return []

    try:
        proc = await asyncio.create_subprocess_exec(
            NODE_BIN, str(AST_WORKER),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(input=js_content.encode("utf-8", errors="replace")),
            timeout=30,
        )
    except asyncio.TimeoutError:
        return []
    except FileNotFoundError:
        return []

    try:
        raw = json.loads(stdout.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return []

    # Support both envelope shapes:
    #   v2 (current): {"findings": [...], "summary": {...}}
    #   v1 (legacy):  [...]
    if isinstance(raw, dict):
        items = raw.get("findings", []) or []
        summary = raw.get("summary")
        if summary:
            SUMMARIES[source_url] = summary
    elif isinstance(raw, list):
        items = raw
    else:
        items = []

    findings = []
    for item in items:
        sev = _ast_severity_map(item.get("severity", "low"))
        cat = item.get("category", "ast")
        name = item.get("name", "Unknown")
        value = str(item.get("value", ""))[:300]
        line = item.get("line", 0)
        note = item.get("note", "")
        tainted = item.get("tainted", False)
        evidence = item.get("evidence", None)

        # Skip pure info-level chunk references -- too noisy unless tainted
        if cat == "chunk" and sev == "low" and not tainted:
            continue

        # Two paths: semantic detectors vs. legacy AST detectors.
        if cat.startswith("semantic:"):
            # Strip "semantic:" prefix for the category but keep "[SEM]" in the name
            # so it's instantly recognizable in terminal output.
            short_cat = cat.replace("semantic:", "", 1)
            findings.append(Finding(
                source_url=source_url,
                category=f"semantic:{short_cat}",
                name=f"[SEM] {name}",
                severity=sev,
                context=short_cat,
                match=value,
                line=line,
                snippet=note or value[:120],
                confidence="high" if (evidence and len(evidence) >= 2) else "pattern+context",
                note=note,
                evidence=evidence,
            ))
            continue

        # Legacy AST finding path -- kept identical to previous behaviour.
        confidence = "high" if tainted else "pattern+context" if note else "pattern"
        findings.append(Finding(
            source_url=source_url,
            category=f"ast:{cat}",
            name=f"[AST] {name}",
            severity=sev,
            context=cat,
            match=value,
            line=line,
            snippet=note or value[:120],
            confidence=confidence,
        ))

    return findings


def score_finding(f: Finding) -> int:
    """
    Numeric priority score for sorting/reporting.
    Factors: severity, confidence, category.
    Semantic findings (from the model-driven detectors) outrank legacy
    regex/AST output for the same severity because they carry more evidence.
    """
    base = SEVERITY_SCORE.get(f.severity, 0)
    conf_bonus = {"high": 20, "pattern+context": 10, "pattern": 0}.get(f.confidence, 0)
    cat_bonus = (
        25 if f.category.startswith("semantic:") else
        15 if f.category == "secrets" else
        10 if f.category == "endpoints" else 0
    )
    return base + conf_bonus + cat_bonus


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Remove duplicate findings across static + AST sources."""
    seen: set[tuple] = set()
    out = []
    for f in findings:
        key = (f.source_url, f.name.replace("[AST] ", ""), f.match[:60])
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out


def classify(findings: list[Finding]) -> list[Finding]:
    """Sort by score descending, deduplicate, return clean list."""
    deduped = deduplicate(findings)
    deduped.sort(key=score_finding, reverse=True)
    return deduped
