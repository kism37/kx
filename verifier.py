"""
kx -- LLM verification pass

Structural detectors give us *candidates*. They sometimes flag a real bug
chain ("client validates X, mutation omits X") on code that's actually fine
(maybe X is only ever computed server-side too). Conversely, they sometimes
report findings that would benefit from a written-out PoC for the report.

This module sends the top-N high/critical semantic findings to Claude
along with their code context, and asks for:

  1. verdict        -- "exploitable" | "likely_exploitable" | "needs_testing"
                      | "false_positive"
  2. cvss           -- rough severity rating
  3. poc            -- a concrete HTTP request the user can paste into Burp
  4. prerequisites  -- auth state, role required, etc.
  5. chain_notes    -- possible chaining with other findings
  6. analyst_note   -- short explanation of the reasoning

It is OPT-IN via `--verify`. Without an API key set, it no-ops silently.

Cost: ~$0.05-$0.15 per finding with Sonnet, depending on context size.
Capped at 25 findings per run by default to bound spend.
"""

import json
import os
import re
from dataclasses import dataclass

import httpx


# Hard cap: this runs against a paid API, never silently blow up cost.
MAX_FINDINGS_PER_RUN = 25
ANTHROPIC_API = "https://api.anthropic.com/v1/messages"
DEFAULT_MODEL = "claude-sonnet-4-5"   # current Claude Sonnet, can override
MAX_TOKENS_OUT = 800


SYSTEM_PROMPT = """You are a senior application security engineer reviewing
findings from a static analysis tool that detects bug-class patterns in
JavaScript. For each finding you receive:

- Read the structural evidence (schema fields, mutation payloads, etc.).
- Read the surrounding code window.
- Decide whether the structural pattern represents a real, exploitable bug.

Your output MUST be a single JSON object with this exact shape:

{
  "verdict":      "exploitable" | "likely_exploitable" | "needs_testing" | "false_positive",
  "cvss_estimate": "0.0" to "10.0" string,
  "poc":          "<exact HTTP request OR null>",
  "prerequisites": "<auth state, role, setup required, OR null>",
  "chain_notes": "<how this might chain with other findings, OR null>",
  "analyst_note": "<2-4 sentence reasoning>"
}

Important rules:
- DO NOT include any prose outside the JSON.
- DO NOT wrap the JSON in markdown fences.
- If you are uncertain, return "needs_testing" rather than guessing high.
- PoCs should be real HTTP request samples, not pseudocode. Include method,
  path, headers, and body where applicable.
- Mark "false_positive" if the structural finding is technically right but
  the actual code (a) revalidates server-side, (b) uses a session-derived
  value, or (c) is otherwise benign in this concrete instance.
- Be conservative on severity. Many findings are useful starting points
  for testing, not confirmed bugs."""


@dataclass
class VerifierResult:
    verdict: str
    cvss_estimate: str
    poc: str | None
    prerequisites: str | None
    chain_notes: str | None
    analyst_note: str

    def to_dict(self) -> dict:
        return {
            "verdict":        self.verdict,
            "cvss_estimate":  self.cvss_estimate,
            "poc":            self.poc,
            "prerequisites":  self.prerequisites,
            "chain_notes":    self.chain_notes,
            "analyst_note":   self.analyst_note,
        }


def _build_user_message(finding, code_window: str) -> str:
    evidence_lines = []
    for ev in (finding.evidence or []):
        kind = ev.get("kind", "?")
        line = ev.get("line", "")
        snip = (ev.get("snippet") or "")[:300]
        evidence_lines.append(f"  - [{kind}] (line {line}): {snip}")
    evidence_block = "\n".join(evidence_lines) if evidence_lines else "  (no structured evidence)"

    return f"""## Finding

- Name:       {finding.name}
- Severity:   {finding.severity}
- Confidence: {finding.confidence}
- Target:     {finding.match}
- Location:   {finding.source_url}:{finding.line}

## Structural evidence
{evidence_block}

## Detector note
{finding.note or "(none)"}

## Code window
```javascript
{code_window}
```

Decide whether this represents a real, exploitable bug. Respond with the
JSON object specified in your instructions and nothing else."""


def _code_window(source: str, around_line: int, lines: int = 60) -> str:
    """Take a ~lines-line window around the target line, falling back to head."""
    if not source:
        return ""
    all_lines = source.splitlines()
    if around_line <= 0 or around_line > len(all_lines):
        # Source is single-line minified or invalid line; cap by characters.
        cap = 3500
        return source[:cap] if len(source) <= cap else source[:cap] + "..."
    start = max(0, around_line - lines // 2)
    end   = min(len(all_lines), start + lines)
    snippet = "\n".join(all_lines[start:end])
    # Always cap at a reasonable character count too -- minified single-line
    # files have huge "single lines" when split fails.
    if len(snippet) > 3500:
        snippet = snippet[:3500] + "..."
    return snippet


def _strip_json(text: str) -> str:
    """Strip markdown fences / surrounding prose to get at the JSON body."""
    text = text.strip()
    # Remove ```json ... ``` or ``` ... ```
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```\s*$", "", text)
    # Some models add a sentence before/after -- grab the first JSON-shaped block
    m = re.search(r"\{.*\}", text, re.DOTALL)
    return m.group(0) if m else text


async def verify_finding(
    finding,
    source_for_finding: str,
    *,
    api_key: str,
    model: str = DEFAULT_MODEL,
    timeout: float = 30.0,
    client: httpx.AsyncClient | None = None,
) -> VerifierResult | None:
    """Send one finding + code window to Claude. Returns parsed result or None."""
    code_window = _code_window(source_for_finding, finding.line)
    user_msg = _build_user_message(finding, code_window)

    payload = {
        "model": model,
        "max_tokens": MAX_TOKENS_OUT,
        "system": SYSTEM_PROMPT,
        "messages": [{"role": "user", "content": user_msg}],
    }
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }

    own_client = client is None
    if own_client:
        client = httpx.AsyncClient(timeout=timeout)
    try:
        r = await client.post(ANTHROPIC_API, headers=headers,
                              content=json.dumps(payload))
        if r.status_code != 200:
            return None
        data = r.json()
        text_parts = [b.get("text","") for b in data.get("content", [])
                      if b.get("type") == "text"]
        text = "\n".join(text_parts).strip()
        if not text:
            return None
        try:
            parsed = json.loads(_strip_json(text))
        except json.JSONDecodeError:
            return None
        return VerifierResult(
            verdict        = str(parsed.get("verdict") or "needs_testing"),
            cvss_estimate  = str(parsed.get("cvss_estimate") or ""),
            poc            = parsed.get("poc"),
            prerequisites  = parsed.get("prerequisites"),
            chain_notes    = parsed.get("chain_notes"),
            analyst_note   = str(parsed.get("analyst_note") or ""),
        )
    except Exception:
        return None
    finally:
        if own_client:
            await client.aclose()


async def verify_findings(
    findings: list,
    sources_by_url: dict[str, str],
    *,
    api_key: str | None = None,
    model: str = DEFAULT_MODEL,
    max_findings: int = MAX_FINDINGS_PER_RUN,
    concurrency: int = 3,
    progress_callback=None,
) -> dict:
    """
    Verify up to `max_findings` of the highest-priority semantic findings.

    Returns a dict: {finding_id_str: VerifierResult.to_dict()}
    Finding IDs are derived as f"{source_url}::{line}::{match}" for stable
    matching back to the original findings.
    """
    import asyncio

    key = api_key or os.getenv("ANTHROPIC_API_KEY")
    if not key:
        return {}

    # Only semantic findings, sorted by severity then confidence
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    conf_rank = {"high": 3, "pattern+context": 2, "pattern": 1}
    candidates = [f for f in findings if f.category.startswith("semantic:")]
    candidates.sort(
        key=lambda f: (sev_rank.get(f.severity, 0), conf_rank.get(f.confidence, 0)),
        reverse=True,
    )
    candidates = candidates[:max_findings]
    if not candidates:
        return {}

    results: dict[str, dict] = {}
    sem = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(timeout=30.0) as client:
        async def _one(f):
            async with sem:
                src = sources_by_url.get(f.source_url, "")
                if progress_callback:
                    progress_callback(f.match)
                res = await verify_finding(
                    f, src, api_key=key, model=model, client=client
                )
                if res:
                    fid = f"{f.source_url}::{f.line}::{f.match}"
                    results[fid] = res.to_dict()
        await asyncio.gather(*[_one(f) for f in candidates])
    return results


def attach_verification_to_findings(findings: list, verifier_results: dict):
    """
    Mutate findings list to embed verifier results into each Finding's
    evidence chain. Safe to call multiple times.
    """
    for f in findings:
        fid = f"{f.source_url}::{f.line}::{f.match}"
        vr = verifier_results.get(fid)
        if not vr:
            continue
        ev = list(f.evidence or [])
        ev.append({
            "kind": "llm_verdict",
            "line": f.line,
            "snippet": (
                f"verdict={vr['verdict']} "
                f"cvss≈{vr['cvss_estimate']} -- "
                f"{vr['analyst_note']}"
            ),
        })
        if vr.get("poc"):
            ev.append({
                "kind": "llm_poc", "line": f.line,
                "snippet": vr["poc"][:1000],
            })
        if vr.get("prerequisites"):
            ev.append({
                "kind": "llm_prereq", "line": f.line,
                "snippet": vr["prerequisites"][:400],
            })
        if vr.get("chain_notes"):
            ev.append({
                "kind": "llm_chain", "line": f.line,
                "snippet": vr["chain_notes"][:400],
            })
        f.evidence = ev
        # Downgrade confidence on false_positive verdicts
        if vr["verdict"] == "false_positive":
            f.confidence = "fp_per_llm"
        elif vr["verdict"] == "exploitable":
            f.confidence = "verified"
