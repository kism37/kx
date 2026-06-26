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
MAX_TOKENS_OUT = 800

# ── Provider registry ───────────────────────────────────────────────────────
# kx verifies findings against *any* LLM, not just Anthropic. We support two
# wire shapes:
#   "anthropic" -> POST /v1/messages         (x-api-key, system+messages)
#   "openai"    -> POST /v1/chat/completions (Bearer, messages[role=system,user])
# The OpenAI-compatible shape covers OpenAI, OpenRouter, Groq, DeepSeek,
# Mistral, Together, Gemini's compat endpoint, and local Ollama / LM Studio --
# so "any API key" is really just these two adapters plus a base-URL override.
#
# Each entry: style, base_url (endpoint), default model, and the env vars to
# search (in order) for a key.
PROVIDERS = {
    "anthropic":  {"style": "anthropic",
                   "base_url": "https://api.anthropic.com/v1/messages",
                   "model": "claude-sonnet-4-6",
                   "envs": ["ANTHROPIC_API_KEY"]},
    "openai":     {"style": "openai",
                   "base_url": "https://api.openai.com/v1/chat/completions",
                   "model": "gpt-4o-mini",
                   "envs": ["OPENAI_API_KEY"]},
    "openrouter": {"style": "openai",
                   "base_url": "https://openrouter.ai/api/v1/chat/completions",
                   "model": "anthropic/claude-3.5-sonnet",
                   "envs": ["OPENROUTER_API_KEY"]},
    "groq":       {"style": "openai",
                   "base_url": "https://api.groq.com/openai/v1/chat/completions",
                   "model": "llama-3.3-70b-versatile",
                   "envs": ["GROQ_API_KEY"]},
    "deepseek":   {"style": "openai",
                   "base_url": "https://api.deepseek.com/v1/chat/completions",
                   "model": "deepseek-chat",
                   "envs": ["DEEPSEEK_API_KEY"]},
    "gemini":     {"style": "openai",
                   "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
                   "model": "gemini-2.0-flash",
                   "envs": ["GEMINI_API_KEY", "GOOGLE_API_KEY"]},
    "mistral":    {"style": "openai",
                   "base_url": "https://api.mistral.ai/v1/chat/completions",
                   "model": "mistral-large-latest",
                   "envs": ["MISTRAL_API_KEY"]},
    "together":   {"style": "openai",
                   "base_url": "https://api.together.xyz/v1/chat/completions",
                   "model": "meta-llama/Llama-3.3-70B-Instruct-Turbo",
                   "envs": ["TOGETHER_API_KEY"]},
}

# Order in which "auto" detection probes env vars when no provider is named.
AUTO_ORDER = ["anthropic", "openai", "openrouter", "groq",
              "deepseek", "gemini", "mistral", "together"]

# Generic env vars an openai-compatible / custom endpoint may use for its key.
_GENERIC_KEY_ENVS = ["OPENAI_API_KEY", "LLM_API_KEY", "KX_VERIFY_API_KEY"]

# Back-compat alias -- some callers/tests import these names directly.
ANTHROPIC_API = PROVIDERS["anthropic"]["base_url"]
DEFAULT_MODEL = PROVIDERS["anthropic"]["model"]


@dataclass
class VerifyConfig:
    """Everything verify_finding needs to talk to one provider."""
    provider: str
    style: str       # "anthropic" | "openai"
    api_key: str
    base_url: str
    model: str
    key_env: str = ""


def resolve_verify_config(provider: str | None = None, model: str | None = None,
                          base_url: str | None = None,
                          api_key: str | None = None) -> "VerifyConfig | None":
    """
    Resolve provider + key + base_url + model from explicit args and the
    environment. Returns a VerifyConfig, or None if no usable API key is found.

    provider:
      - None / "auto"  -> probe AUTO_ORDER env vars, first key wins.
      - a known name   -> use that provider's registry entry.
      - "openai-compatible" / "custom" / unknown name + base_url -> generic
        OpenAI-shaped endpoint at base_url (key from api_key or generic envs).
    """
    name = (provider or "auto").strip().lower()

    def _generic(prov_label: str) -> "VerifyConfig | None":
        key = api_key
        env_used = ""
        if not key:
            for env in _GENERIC_KEY_ENVS:
                if os.getenv(env):
                    key, env_used = os.getenv(env), env
                    break
        if not key or not base_url:
            return None
        return VerifyConfig(prov_label, "openai", key, base_url,
                            model or "gpt-4o-mini", env_used)

    if name in ("openai-compatible", "compatible", "custom"):
        return _generic("custom")

    if name == "auto":
        for cand in AUTO_ORDER:
            for env in PROVIDERS[cand]["envs"]:
                if os.getenv(env):
                    name = cand
                    break
            if name != "auto":
                break
        if name == "auto":
            # No known key. A bare --verify-base-url + generic key still works.
            return _generic("custom")

    spec = PROVIDERS.get(name)
    if not spec:
        # Unknown provider name: treat as openai-compatible if we have an endpoint.
        return _generic(name)

    key, key_env = api_key, ""
    if not key:
        for env in spec["envs"]:
            if os.getenv(env):
                key, key_env = os.getenv(env), env
                break
    if not key:
        return None
    return VerifyConfig(name, spec["style"], key,
                        base_url or spec["base_url"],
                        model or spec["model"],
                        key_env or spec["envs"][0])


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


async def _call_anthropic(system: str, user_msg: str, config: "VerifyConfig",
                          client: httpx.AsyncClient) -> str | None:
    """Anthropic /v1/messages. Returns the assistant text or None."""
    payload = {
        "model": config.model,
        "max_tokens": MAX_TOKENS_OUT,
        "system": system,
        "messages": [{"role": "user", "content": user_msg}],
    }
    headers = {
        "x-api-key": config.api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    r = await client.post(config.base_url, headers=headers,
                          content=json.dumps(payload))
    if r.status_code != 200:
        return None
    data = r.json()
    parts = [b.get("text", "") for b in data.get("content", [])
             if b.get("type") == "text"]
    return "\n".join(parts).strip() or None


async def _call_openai(system: str, user_msg: str, config: "VerifyConfig",
                       client: httpx.AsyncClient) -> str | None:
    """OpenAI-compatible /v1/chat/completions. Returns the message text or None."""
    headers = {
        "Authorization": f"Bearer {config.api_key}",
        "content-type": "application/json",
    }
    body = {
        "model": config.model,
        "max_tokens": MAX_TOKENS_OUT,
        "temperature": 0,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user_msg},
        ],
    }
    # Prefer enforced JSON output; retry without it if the provider rejects the
    # field (some OpenAI-compatible backends 400 on response_format).
    r = await client.post(config.base_url, headers=headers,
                          content=json.dumps({**body, "response_format": {"type": "json_object"}}))
    if r.status_code == 400:
        r = await client.post(config.base_url, headers=headers,
                              content=json.dumps(body))
    if r.status_code != 200:
        return None
    try:
        return (r.json()["choices"][0]["message"]["content"] or "").strip() or None
    except (KeyError, IndexError, TypeError):
        return None


async def verify_finding(
    finding,
    source_for_finding: str,
    *,
    config: "VerifyConfig",
    timeout: float = 30.0,
    client: httpx.AsyncClient | None = None,
) -> VerifierResult | None:
    """Send one finding + code window to the configured LLM. Parsed result or None."""
    code_window = _code_window(source_for_finding, finding.line)
    user_msg = _build_user_message(finding, code_window)

    own_client = client is None
    if own_client:
        client = httpx.AsyncClient(timeout=timeout)
    try:
        if config.style == "anthropic":
            text = await _call_anthropic(SYSTEM_PROMPT, user_msg, config, client)
        else:
            text = await _call_openai(SYSTEM_PROMPT, user_msg, config, client)
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
    config: "VerifyConfig | None" = None,
    max_findings: int = MAX_FINDINGS_PER_RUN,
    concurrency: int = 3,
    progress_callback=None,
) -> dict:
    """
    Verify up to `max_findings` of the highest-priority semantic findings.

    `config` selects the provider/model/key (see resolve_verify_config). If
    omitted, we auto-detect from the environment. Returns a dict:
    {finding_id_str: VerifierResult.to_dict()} keyed by
    f"{source_url}::{line}::{match}" for stable matching back to the findings.
    """
    import asyncio

    cfg = config or resolve_verify_config()
    if cfg is None or not cfg.api_key:
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
                res = await verify_finding(f, src, config=cfg, client=client)
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
