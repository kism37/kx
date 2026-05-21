"""
kx -- Static Extractor
"""

import re
import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "patterns"))
from signatures import SIGNATURES

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


@dataclass
class Finding:
    source_url: str
    category: str
    name: str
    severity: str
    context: str
    match: str
    line: int
    snippet: str
    confidence: str = "pattern"
    # Optional semantic-detector enrichments. Legacy code paths leave these
    # as defaults; semantic findings populate them.
    note: str = ""
    evidence: list = None  # list[dict{kind, line, snippet}]
    # Triage state. Populated by auto_triage after classification; can be
    # overridden by the operator via the REPL or HTML report.
    #   "real"    -- high-confidence true positive worth chasing
    #   "verify"  -- needs human verification, default for most things
    #   "fp"      -- auto-classified as framework / library noise
    #   ""        -- untriaged (initial state)
    verdict: str = ""
    verdict_reason: str = ""  # short human-readable explanation of the auto-call

    def to_dict(self) -> dict:
        d = {
            "source_url": self.source_url,
            "category": self.category,
            "name": self.name,
            "severity": self.severity,
            "context": self.context,
            "match": self.match,
            "line": self.line,
            "snippet": self.snippet,
            "confidence": self.confidence,
        }
        if self.note:
            d["note"] = self.note
        if self.evidence:
            d["evidence"] = self.evidence
        if self.verdict:
            d["verdict"] = self.verdict
            d["verdict_reason"] = self.verdict_reason
        return d


def _compile_signatures(sigs: dict) -> dict:
    compiled = {}
    for category, patterns in sigs.items():
        compiled[category] = []
        for p in patterns:
            try:
                compiled[category].append({**p, "_re": re.compile(p["pattern"], re.MULTILINE)})
            except re.error as e:
                print(f"[!] Bad pattern '{p['name']}': {e}", file=sys.stderr)
    return compiled


_SIGS = _compile_signatures(SIGNATURES)

_FP_FILTERS = [
    re.compile(r'example\.com', re.I),
    re.compile(r'placeholder', re.I),
    re.compile(r'YOUR_API_KEY', re.I),
    re.compile(r'<YOUR', re.I),
    re.compile(r'xxx+', re.I),
    re.compile(r'1234567890'),
    re.compile(r'AAAAAAAAAAAAAAAA'),
]


def _is_fp(match_str: str) -> bool:
    return any(p.search(match_str) for p in _FP_FILTERS)


def _get_line_number(content: str, pos: int) -> int:
    return content[:pos].count("\n") + 1


def _get_snippet(content: str, start: int, end: int, radius: int = 120) -> str:
    s = max(0, start - radius)
    e = min(len(content), end + radius)
    return content[s:e].replace("\n", " ").replace("\r", "").strip()


def _boost_confidence(match_str: str, category: str, content: str, pos: int) -> str:
    snippet = content[max(0, pos - 200):pos + 200]
    if category == "secrets":
        if re.search(r'(fetch|axios|XMLHttpRequest|\.get|\.post)\b', snippet):
            return "pattern+context"
        if re.search(r'(const|let|var|=)\s', snippet):
            return "pattern+context"
    if category == "sinks":
        if re.search(r'(location\.|params\.|query\.|req\.|request\.)', snippet):
            return "high"
    if category == "endpoints":
        if re.search(r'(admin|internal|secret|private|manage)', snippet, re.I):
            return "pattern+context"
    return "pattern"


def extract(source_url: str, content: str) -> list:
    findings = []
    seen: set = set()

    for category, patterns in _SIGS.items():
        for sig in patterns:
            for m in sig["_re"].finditer(content):
                match_str = m.group(0).strip()
                key = (source_url, sig["name"], match_str[:80])
                if key in seen:
                    continue
                seen.add(key)
                if _is_fp(match_str):
                    continue
                display_match = match_str if len(match_str) <= 200 else match_str[:200] + "..."
                findings.append(Finding(
                    source_url=source_url,
                    category=category,
                    name=sig["name"],
                    severity=sig["severity"],
                    context=sig.get("context", ""),
                    match=display_match,
                    line=_get_line_number(content, m.start()),
                    snippet=_get_snippet(content, m.start(), m.end()),
                    confidence=_boost_confidence(match_str, category, content, m.start()),
                ))

    findings.sort(key=lambda f: -SEVERITY_RANK.get(f.severity, 0))
    return findings
