"""
kx -- HTML report generator

Designed for a hunter triaging findings, not for a manager counting bugs.
Single self-contained .html file. No external assets. Works offline.

Layout (top to bottom):
  1. Header strip: target, scan time, totals, severity histogram
  2. Triage block: the 5 highest-priority semantic findings, expanded by
     default, with copy-able PoCs from the LLM verifier when present
  3. Per-file groups: every JS file collapsed by default, expanded on click;
     each shows the semantic summary (schemas, mutations, network calls) and
     all findings inline with evidence
  4. All-findings table at bottom for keyword search / sorting

Toolbar persistent at top with severity + category + file filters.
"""

from __future__ import annotations
import html
import json
from collections import defaultdict, Counter
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse

from extractor import Finding


# ─── helpers ────────────────────────────────────────────────────────────────

SEV_ORDER = ["critical", "high", "medium", "low", "info"]
SEV_RANK = {s: i for i, s in enumerate(reversed(SEV_ORDER))}

def _esc(s) -> str:
    return html.escape(str(s) if s is not None else "")

def _short_url(url: str, n: int = 60) -> str:
    if url.startswith("sourcemap://"):
        path = url.split("#", 1)[1] if "#" in url else url
        return f"[src] {path}" if len(path) < n - 6 else "[src] ..." + path[-(n-9):]
    if len(url) <= n: return url
    return "..." + url[-(n-1):]

def _basename(url: str) -> str:
    if url.startswith("sourcemap://") and "#" in url:
        return url.split("#",1)[1]
    p = urlparse(url)
    return p.path.rsplit("/", 1)[-1] or p.netloc


# ─── CSS (inline) ───────────────────────────────────────────────────────────

CSS = r"""
:root {
  --bg: #0d1117;
  --bg-elev: #161b22;
  --bg-elev-2: #1c2230;
  --border: #30363d;
  --border-soft: #21262d;
  --fg: #e6edf3;
  --fg-dim: #8b949e;
  --fg-strong: #f0f6fc;
  --accent: #58a6ff;
  --critical: #ff6b6b;
  --high: #ff9558;
  --medium: #d29922;
  --low: #58a6ff;
  --info: #6e7681;
  --ok: #3fb950;
  --code-bg: #0a0e14;
  --mono: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
  --sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
}
@media (prefers-color-scheme: light) {
  :root.auto {
    --bg: #fafbfc; --bg-elev: #ffffff; --bg-elev-2: #f6f8fa;
    --border: #d0d7de; --border-soft: #e3e6ea;
    --fg: #1f2328; --fg-dim: #59636e; --fg-strong: #0d1117;
    --accent: #0969da; --code-bg: #f6f8fa;
  }
}
* { box-sizing: border-box; }
html, body {
  margin: 0; padding: 0;
  background: var(--bg); color: var(--fg);
  font-family: var(--sans); font-size: 14px; line-height: 1.55;
  -webkit-font-smoothing: antialiased;
}
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; }
code, pre { font-family: var(--mono); font-size: 12.5px; }
pre {
  background: var(--code-bg); padding: 12px 14px;
  border-radius: 6px; overflow-x: auto;
  border: 1px solid var(--border-soft);
  margin: 8px 0;
}
.container { max-width: 1280px; margin: 0 auto; padding: 24px 28px 80px; }

/* Header */
.header {
  display: flex; align-items: flex-start; justify-content: space-between;
  gap: 24px; padding-bottom: 20px; border-bottom: 1px solid var(--border);
  margin-bottom: 24px;
}
.header h1 {
  font-family: var(--mono); font-size: 32px; font-weight: 700;
  margin: 0 0 4px 0; color: var(--ok); letter-spacing: -.5px;
}
.header .target {
  font-family: var(--mono); font-size: 13px; color: var(--fg-dim);
}
.header .meta {
  display: flex; gap: 8px; flex-wrap: wrap; margin-top: 10px;
}
.header .meta span {
  background: var(--bg-elev); border: 1px solid var(--border-soft);
  padding: 3px 10px; border-radius: 999px; font-size: 12px; color: var(--fg-dim);
  font-family: var(--mono);
}
.header .actions { display: flex; gap: 8px; }
.btn {
  background: var(--bg-elev); border: 1px solid var(--border);
  color: var(--fg); padding: 6px 12px; border-radius: 6px;
  font-size: 12px; cursor: pointer; font-family: inherit;
}
.btn:hover { border-color: var(--accent); color: var(--fg-strong); }

/* Severity tiles */
.sev-grid {
  display: grid; grid-template-columns: repeat(6, 1fr); gap: 12px; margin-bottom: 28px;
}
.tile {
  background: var(--bg-elev); border: 1px solid var(--border-soft);
  border-radius: 10px; padding: 14px 16px;
}
.tile .label { font-size: 10.5px; color: var(--fg-dim); letter-spacing: 1.2px;
  text-transform: uppercase; font-weight: 600; }
.tile .value { font-size: 30px; font-weight: 700; line-height: 1.1; margin-top: 6px;
  font-family: var(--mono); }
.tile.critical .value { color: var(--critical); }
.tile.high     .value { color: var(--high); }
.tile.medium   .value { color: var(--medium); }
.tile.low      .value { color: var(--low); }
.tile.total    .value { color: var(--fg-strong); }
.tile.files    .value { color: var(--fg-strong); }
.tile .zero    { opacity: 0.35; }

/* Section heading */
section { margin-bottom: 32px; }
section > h2 {
  font-size: 11px; font-weight: 700; letter-spacing: 1.5px;
  text-transform: uppercase; color: var(--fg-dim);
  margin: 0 0 12px 0; padding: 0 0 8px 0;
  border-bottom: 1px solid var(--border-soft);
}
section > h2 .count {
  float: right; font-weight: 500; color: var(--fg-dim);
}

/* Triage cards (top-priority findings) */
.triage-card {
  background: var(--bg-elev);
  border: 1px solid var(--border);
  border-left: 3px solid var(--high);
  border-radius: 8px;
  padding: 16px 18px; margin-bottom: 12px;
}
.triage-card.critical { border-left-color: var(--critical); }
.triage-card.high     { border-left-color: var(--high); }
.triage-card.medium   { border-left-color: var(--medium); }
.triage-card .row1 {
  display: flex; align-items: baseline; gap: 12px; margin-bottom: 6px;
  flex-wrap: wrap;
}
.triage-card .name { font-size: 15px; font-weight: 600; color: var(--fg-strong); }
.triage-card .match {
  font-family: var(--mono); color: var(--high); background: rgba(255,149,88,.08);
  padding: 1px 7px; border-radius: 4px; font-size: 12.5px;
}
.triage-card.critical .match { color: var(--critical); background: rgba(255,107,107,.1); }
.triage-card.medium   .match { color: var(--medium);  background: rgba(210,153,34,.1); }
.triage-card .loc {
  font-family: var(--mono); font-size: 11px; color: var(--fg-dim);
  margin-left: auto;
}
.triage-card .note {
  color: var(--fg); margin: 8px 0 12px 0; max-width: 90ch;
}
.triage-card details summary {
  cursor: pointer; color: var(--fg-dim); font-size: 12px;
  user-select: none; padding: 4px 0;
}
.triage-card details summary:hover { color: var(--fg); }
.triage-card details[open] summary { color: var(--fg-strong); }
.evidence {
  margin: 8px 0 0 0; padding: 10px 14px;
  background: var(--bg-elev-2); border-radius: 6px;
  font-family: var(--mono); font-size: 12px;
}
.evidence .ev-line { display: flex; gap: 10px; padding: 3px 0; align-items: flex-start; }
.evidence .ev-kind {
  color: var(--fg-dim); min-width: 140px; flex-shrink: 0;
  font-weight: 600;
}
.evidence .ev-snip { color: var(--fg); word-break: break-all; flex: 1; }
.evidence .ev-snip .num { color: var(--fg-dim); font-weight: 400; }
.verdict {
  display: inline-block; font-size: 11px; font-weight: 600;
  padding: 1px 8px; border-radius: 4px; margin-left: 8px;
}
.verdict.exploitable        { background: rgba(255,107,107,.15); color: var(--critical); }
.verdict.likely_exploitable { background: rgba(255,149,88,.15); color: var(--high); }
.verdict.needs_testing      { background: rgba(210,153,34,.15); color: var(--medium); }
.verdict.false_positive     { background: rgba(110,118,129,.2); color: var(--fg-dim); }

/* Per-file groups */
.file-group {
  background: var(--bg-elev); border: 1px solid var(--border-soft);
  border-radius: 8px; margin-bottom: 10px; overflow: hidden;
}
.file-group > summary {
  list-style: none; cursor: pointer; padding: 12px 16px;
  display: flex; align-items: center; gap: 12px;
  background: var(--bg-elev);
  border-bottom: 1px solid transparent;
}
.file-group[open] > summary { border-bottom-color: var(--border-soft); }
.file-group > summary::-webkit-details-marker { display: none; }
.file-group > summary::before {
  content: "▸"; color: var(--fg-dim); font-size: 10px;
  transition: transform .15s;
}
.file-group[open] > summary::before { transform: rotate(90deg); display: inline-block; }
.file-group .fname {
  font-family: var(--mono); font-size: 13px; color: var(--fg-strong);
  flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
}
.file-group .fname .src-tag {
  display: inline-block; background: rgba(63,185,80,.12); color: var(--ok);
  font-size: 10px; padding: 1px 6px; border-radius: 3px;
  margin-right: 6px; font-weight: 600;
}
.file-group .findings-sum {
  display: flex; gap: 6px; align-items: center; font-size: 11px;
  font-family: var(--mono);
}
.pill {
  background: var(--bg-elev-2); color: var(--fg-dim);
  padding: 2px 7px; border-radius: 4px;
  border: 1px solid var(--border-soft);
}
.pill.critical { color: var(--critical); border-color: rgba(255,107,107,.3); }
.pill.high     { color: var(--high);     border-color: rgba(255,149,88,.3); }
.pill.medium   { color: var(--medium);   border-color: rgba(210,153,34,.3); }
.pill.low      { color: var(--low);      border-color: rgba(88,166,255,.2); }
.file-body { padding: 14px 18px; }
.file-body .summary-block {
  background: var(--bg-elev-2); padding: 12px 14px; border-radius: 6px;
  margin-bottom: 14px; font-size: 13px;
}
.file-body .summary-block h4 {
  margin: 0 0 6px 0; font-size: 11px; font-weight: 700;
  letter-spacing: 1.2px; text-transform: uppercase; color: var(--fg-dim);
}
.file-body .summary-block h4:not(:first-child) { margin-top: 12px; }
.file-body .summary-block ul { margin: 0; padding-left: 20px; }
.file-body .summary-block li { margin: 2px 0; }
.file-body .summary-block code { color: var(--fg-strong); }
.file-body .finding {
  border-top: 1px solid var(--border-soft);
  padding: 12px 0;
}
.file-body .finding:first-child { border-top: 0; padding-top: 4px; }
.finding .row1 {
  display: flex; align-items: baseline; gap: 10px; flex-wrap: wrap; margin-bottom: 4px;
}

/* Severity badge */
.sev {
  display: inline-block; font-size: 10px; font-weight: 700; letter-spacing: 1px;
  padding: 2px 8px; border-radius: 3px; min-width: 56px; text-align: center;
  font-family: var(--mono);
}
.sev.critical { background: var(--critical); color: #111; }
.sev.high     { background: var(--high);     color: #111; }
.sev.medium   { background: var(--medium);   color: #111; }
.sev.low      { background: var(--low);      color: #111; }
.sev.info     { background: var(--info);     color: #fff; }

/* Filter toolbar */
.toolbar {
  position: sticky; top: 0; z-index: 10;
  background: var(--bg);
  display: flex; gap: 8px; padding: 12px 0; margin-bottom: 16px;
  border-bottom: 1px solid var(--border-soft); flex-wrap: wrap;
  align-items: center;
}
.toolbar input[type="search"] {
  background: var(--bg-elev); border: 1px solid var(--border);
  color: var(--fg); padding: 6px 12px; border-radius: 6px;
  font-family: inherit; font-size: 13px; min-width: 220px;
  flex: 1; max-width: 360px;
}
.toolbar input[type="search"]:focus { outline: none; border-color: var(--accent); }
.chip {
  background: var(--bg-elev); border: 1px solid var(--border);
  color: var(--fg-dim); padding: 5px 11px; border-radius: 999px;
  font-size: 11.5px; cursor: pointer; user-select: none;
  font-family: var(--mono);
}
.chip.active { background: var(--ok); color: #111; border-color: var(--ok); font-weight: 600; }
.chip.active.critical { background: var(--critical); }
.chip.active.high     { background: var(--high); }
.chip.active.medium   { background: var(--medium); }
.chip.active.low      { background: var(--low); }
.chip:hover { color: var(--fg); }

/* Hidden state for filter */
.hidden { display: none !important; }

/* Empty-state */
.empty {
  text-align: center; padding: 50px 0; color: var(--fg-dim);
}
"""

# ─── JS (inline) ────────────────────────────────────────────────────────────

JS = r"""
(() => {
  const $$ = (s, r=document) => Array.from(r.querySelectorAll(s));

  const sevChips = $$(".chip[data-sev]");
  const catChips = $$(".chip[data-cat]");
  const search   = document.getElementById("search");
  const fileGroups = $$(".file-group");
  const cards    = $$(".triage-card");
  const tableRows = $$(".all-table tbody tr");

  const state = { sev: new Set(["critical","high","medium","low","info"]),
                  cat: new Set(),  // empty = all categories
                  q: "" };

  function rebuildCats() {
    // Default: all on. Build set if any chip is explicitly toggled.
  }

  function findingMatches(el) {
    const sev = el.dataset.sev;
    const cat = el.dataset.cat || "";
    const text = (el.dataset.search || "").toLowerCase();
    if (!state.sev.has(sev)) return false;
    if (state.cat.size && !state.cat.has(cat)) {
      // also allow category prefix matching (semantic:* vs semantic:idor)
      let any = false;
      for (const c of state.cat) {
        if (cat === c || cat.startsWith(c + ":") || c.startsWith(cat + ":")) { any = true; break; }
      }
      if (!any) return false;
    }
    if (state.q && !text.includes(state.q)) return false;
    return true;
  }

  function applyFilter() {
    // Triage cards
    cards.forEach(c => c.classList.toggle("hidden", !findingMatches(c)));
    // Per-file groups: show file if it has any visible finding
    fileGroups.forEach(g => {
      const findings = $$(".finding", g);
      let any = false;
      findings.forEach(f => {
        const visible = findingMatches(f);
        f.classList.toggle("hidden", !visible);
        if (visible) any = true;
      });
      g.classList.toggle("hidden", !any);
    });
    // Table
    tableRows.forEach(r => r.classList.toggle("hidden", !findingMatches(r)));
  }

  sevChips.forEach(c => c.addEventListener("click", () => {
    const sev = c.dataset.sev;
    if (state.sev.has(sev)) state.sev.delete(sev);
    else state.sev.add(sev);
    c.classList.toggle("active", state.sev.has(sev));
    applyFilter();
  }));

  catChips.forEach(c => c.addEventListener("click", () => {
    const cat = c.dataset.cat;
    if (state.cat.has(cat)) state.cat.delete(cat);
    else state.cat.add(cat);
    c.classList.toggle("active", state.cat.has(cat));
    applyFilter();
  }));

  search.addEventListener("input", () => {
    state.q = search.value.trim().toLowerCase();
    applyFilter();
  });

  document.getElementById("expand-all").addEventListener("click", () => {
    fileGroups.forEach(g => g.open = true);
  });
  document.getElementById("collapse-all").addEventListener("click", () => {
    fileGroups.forEach(g => g.open = false);
  });

  // Copy buttons
  $$(".copy-btn").forEach(btn => btn.addEventListener("click", () => {
    const t = btn.dataset.copy || btn.previousElementSibling.innerText;
    navigator.clipboard.writeText(t).then(() => {
      const orig = btn.innerText;
      btn.innerText = "✓ copied";
      setTimeout(() => btn.innerText = orig, 1100);
    });
  }));

  // Keyboard: / focuses search
  window.addEventListener("keydown", e => {
    if (e.key === "/" && document.activeElement !== search) {
      e.preventDefault(); search.focus();
    }
  });
})();
"""

# ─── render fragments ──────────────────────────────────────────────────────

def _render_evidence(f: Finding) -> str:
    if not f.evidence: return ""
    rows = []
    for ev in f.evidence:
        kind = _esc(ev.get("kind", "?"))
        line = ev.get("line", "")
        snip = _esc(ev.get("snippet", ""))
        if len(snip) > 320: snip = snip[:320] + "..."
        line_html = f'<span class="num">L{line}</span> ' if line else ""
        rows.append(
            f'<div class="ev-line">'
            f'<span class="ev-kind">{kind}</span>'
            f'<span class="ev-snip">{line_html}{snip}</span>'
            f'</div>'
        )
    return f'<div class="evidence">{"".join(rows)}</div>'


def _extract_verdict(f: Finding) -> tuple[str | None, str | None, str | None]:
    """Find LLM verifier evidence among the finding's evidence chain."""
    verdict = poc = analyst = None
    for ev in (f.evidence or []):
        kind = ev.get("kind", "")
        snip = ev.get("snippet", "")
        if kind == "llm_verdict":
            # snippet format: verdict=X cvss≈Y -- <note>
            m = snip.split(" ", 2)
            if m and m[0].startswith("verdict="):
                verdict = m[0].replace("verdict=", "")
                analyst = snip.split("--", 1)[1].strip() if "--" in snip else None
        elif kind == "llm_poc":
            poc = snip
    return verdict, poc, analyst


def _render_triage_card(f: Finding) -> str:
    sev_cls = f.severity if f.severity in SEV_ORDER else "info"
    verdict, poc, _ = _extract_verdict(f)
    verdict_html = ""
    if verdict:
        verdict_html = f'<span class="verdict {_esc(verdict)}">{_esc(verdict.replace("_", " "))}</span>'

    poc_html = ""
    if poc:
        poc_html = (
            f'<details><summary>PoC (suggested)</summary>'
            f'<pre>{_esc(poc)}</pre>'
            f'<button class="btn copy-btn" data-copy="{_esc(poc)}">copy</button>'
            f'</details>'
        )

    return (
        f'<div class="triage-card {sev_cls}" data-sev="{sev_cls}" '
        f'data-cat="{_esc(f.category)}" data-search="{_esc(f.name.lower() + " " + f.match.lower() + " " + (f.note or "").lower())}">'
        f'<div class="row1">'
        f'<span class="sev {sev_cls}">{f.severity.upper()}</span>'
        f'<span class="name">{_esc(f.name)}</span>'
        f'{verdict_html}'
        f'<span class="match">{_esc(f.match)}</span>'
        f'<span class="loc">{_esc(_short_url(f.source_url, 70))} · L{f.line}</span>'
        f'</div>'
        f'{("<div class=\"note\">" + _esc(f.note) + "</div>") if f.note else ""}'
        f'{poc_html}'
        f'{("<details><summary>Evidence chain (" + str(len(f.evidence)) + ")</summary>" + _render_evidence(f) + "</details>") if f.evidence else ""}'
        f'</div>'
    )


def _render_summary_block(summary: dict) -> str:
    if not summary: return ""
    parts = []

    schemas = summary.get("schemas", [])
    if schemas:
        items = []
        for s in schemas:
            top = ", ".join(s.get("topFields", [])[:8]) or "--"
            refines = ""
            if s.get("refines"):
                refines = "<ul>" + "".join(
                    f'<li><code>.refine()</code> on <code>{_esc(r.get("path") or "?")}</code>: <em>{_esc(r.get("message") or "")}</em></li>'
                    for r in s["refines"]
                ) + "</ul>"
            items.append(
                f'<li><code>{_esc(s["name"])}</code> ({s["fieldCount"]} fields) -- '
                f'top: <code>{_esc(top)}</code>{refines}</li>'
            )
        parts.append(f'<h4>Schemas</h4><ul>{"".join(items)}</ul>')

    mutations = summary.get("mutations", [])
    if mutations:
        items = []
        for m in mutations:
            for p in m.get("payloads", []):
                keys = ", ".join(p.get("keys", [])) or "--"
                spreads = ", ".join(p.get("spreads", [])) or "--"
                # Field-origin breakdown
                origin_lines = []
                for fr in p.get("fieldsResolved", []):
                    if fr["key"] == "...": continue
                    origin_lines.append(
                        f'<li><code>{_esc(fr["key"])}</code> ← '
                        f'<em>{_esc(fr["originType"])}</em>'
                        f'{": <code>" + _esc(fr["originName"]) + "</code>" if fr.get("originName") else ""}</li>'
                    )
                origins_html = ("<ul>" + "".join(origin_lines) + "</ul>") if origin_lines else ""
                items.append(
                    f'<li><code>{_esc(m["varName"])}</code> (L{p["line"]}) -- '
                    f'keys: <code>{_esc(keys)}</code>, spread: <code>{_esc(spreads)}</code>'
                    f'{origins_html}</li>'
                )
        if items:
            parts.append(f'<h4>Mutations</h4><ul>{"".join(items)}</ul>')

    netcalls = summary.get("networkCalls", [])
    if netcalls:
        items = []
        for n in netcalls:
            url = n.get("urlString") or "<em>dynamic</em>"
            keys = ", ".join(n.get("bodyKeys", [])) or "--"
            items.append(
                f'<li><code>{_esc(n["kind"])}</code> → <code>{_esc(url)}</code> '
                f'(L{n["line"]}) -- body: <code>{_esc(keys)}</code></li>'
            )
        parts.append(f'<h4>Network calls</h4><ul>{"".join(items)}</ul>')

    sessions = summary.get("sessionRefs", [])
    if sessions:
        names = ", ".join(s["varName"] for s in sessions)
        parts.append(f'<h4>Session refs</h4><p><code>{_esc(names)}</code></p>')

    if not parts: return ""
    return f'<div class="summary-block">{"".join(parts)}</div>'


def _render_finding_inline(f: Finding) -> str:
    sev_cls = f.severity if f.severity in SEV_ORDER else "info"
    verdict, _, _ = _extract_verdict(f)
    verdict_html = f'<span class="verdict {_esc(verdict)}">{_esc(verdict.replace("_"," "))}</span>' if verdict else ""
    search_text = (f.name.lower() + " " + f.match.lower() + " " + (f.note or "").lower())
    return (
        f'<div class="finding" data-sev="{sev_cls}" data-cat="{_esc(f.category)}" '
        f'data-search="{_esc(search_text)}">'
        f'<div class="row1">'
        f'<span class="sev {sev_cls}">{f.severity.upper()}</span>'
        f'<span class="name">{_esc(f.name)}</span>'
        f'{verdict_html}'
        f'<span class="match">{_esc(f.match)}</span>'
        f'<span class="loc" style="margin-left:auto">L{f.line}</span>'
        f'</div>'
        f'{("<div class=\"note\">" + _esc(f.note) + "</div>") if f.note else ""}'
        f'{_render_evidence(f)}'
        f'</div>'
    )


def _render_file_group(url: str, file_findings: list[Finding], summary: dict | None) -> str:
    counts = Counter(f.severity for f in file_findings)
    pills = []
    for sev in SEV_ORDER:
        if counts.get(sev):
            pills.append(f'<span class="pill {sev}">{counts[sev]} {sev}</span>')
    pills_html = " ".join(pills) or '<span class="pill">model only</span>'

    name = _basename(url)
    src_tag = '<span class="src-tag">[src]</span>' if url.startswith("sourcemap://") else ""

    sorted_findings = sorted(file_findings, key=lambda f: (-SEV_RANK.get(f.severity, 0), f.line or 0))
    findings_html = "".join(_render_finding_inline(f) for f in sorted_findings) \
                    if sorted_findings else '<div class="empty" style="padding:18px 0">No findings in this file.</div>'

    return (
        f'<details class="file-group">'
        f'<summary>'
        f'<span class="fname">{src_tag}{_esc(name)}</span>'
        f'<span class="findings-sum">{pills_html}</span>'
        f'</summary>'
        f'<div class="file-body">'
        f'{_render_summary_block(summary or {})}'
        f'{findings_html}'
        f'</div>'
        f'</details>'
    )


def _render_table_row(f: Finding) -> str:
    sev_cls = f.severity if f.severity in SEV_ORDER else "info"
    search_text = (f.name.lower() + " " + f.match.lower() + " " + (f.note or "").lower())
    return (
        f'<tr data-sev="{sev_cls}" data-cat="{_esc(f.category)}" '
        f'data-search="{_esc(search_text)}">'
        f'<td><span class="sev {sev_cls}">{f.severity.upper()}</span></td>'
        f'<td><code>{_esc(f.category)}</code></td>'
        f'<td>{_esc(f.name)}</td>'
        f'<td><code>{_esc(f.match[:80])}</code></td>'
        f'<td>L{f.line}</td>'
        f'<td><code style="font-size:11px">{_esc(_short_url(f.source_url, 50))}</code></td>'
        f'</tr>'
    )


# ─── main entry ────────────────────────────────────────────────────────────

def export_html(
    target: str,
    findings: list[Finding],
    rt_findings: list,
    summaries: dict[str, dict],
    path: Path,
    *,
    triage_count: int = 5,
) -> None:
    findings_sorted = sorted(
        findings,
        key=lambda f: (-SEV_RANK.get(f.severity, 0),
                       0 if f.category.startswith("semantic:") else 1,
                       f.source_url or "",
                       f.line or 0)
    )

    # Severity tallies
    sev_counts = Counter(f.severity for f in findings)
    cat_counts = Counter(f.category for f in findings)

    # Pick top triage: highest severity semantic findings, capped
    triage = [f for f in findings_sorted
              if f.category.startswith("semantic:")
              and f.severity in ("critical", "high")][:triage_count]

    # Findings by file (excluding triage-already-shown if you wanted to dedup;
    # we keep them so per-file view is complete)
    by_file: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        by_file[f.source_url].append(f)

    # Files with findings, sorted by max severity in that file
    file_max_sev = {
        u: max((SEV_RANK.get(f.severity, 0) for f in fs), default=0)
        for u, fs in by_file.items()
    }
    file_urls_sorted = sorted(
        set(by_file.keys()) | set(summaries.keys()),
        key=lambda u: (-file_max_sev.get(u, -1), u)
    )

    # Build chip lists
    # Severity chips (always all five)
    sev_chips = "".join(
        f'<span class="chip active {s}" data-sev="{s}">'
        f'{s} <span style="opacity:.7">{sev_counts.get(s,0)}</span>'
        f'</span>'
        for s in SEV_ORDER if sev_counts.get(s, 0) or s in ("critical","high","medium")
    )
    # Top categories
    cat_chips = "".join(
        f'<span class="chip" data-cat="{_esc(c)}">{_esc(c.replace("semantic:","").replace("ast:",""))} '
        f'<span style="opacity:.6">{n}</span></span>'
        for c, n in cat_counts.most_common(8)
    )

    # Triage section
    triage_html = "".join(_render_triage_card(f) for f in triage) if triage \
                  else '<div class="empty">No critical or high semantic findings.</div>'

    # Per-file section
    files_html = "".join(
        _render_file_group(u, by_file.get(u, []), summaries.get(u))
        for u in file_urls_sorted
    )

    # Full table at the bottom
    table_rows = "".join(_render_table_row(f) for f in findings_sorted)

    # Runtime requests panel
    rt_html = ""
    if rt_findings:
        rt_rows = "".join(
            f'<tr><td>{_esc(r.type)}</td><td>{_esc(r.method)}</td>'
            f'<td><code>{_esc(r.url)}</code></td></tr>'
            for r in rt_findings
        )
        rt_html = (
            f'<section><h2>Runtime captures <span class="count">{len(rt_findings)}</span></h2>'
            f'<table class="all-table" style="width:100%;border-collapse:collapse">'
            f'<thead><tr><th>Type</th><th>Method</th><th>URL</th></tr></thead>'
            f'<tbody>{rt_rows}</tbody></table></section>'
        )

    js_files_count = len({f.source_url for f in findings} | set(summaries.keys()))

    document = f"""<!doctype html>
<html lang="en" class="auto">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>kx -- {_esc(target)}</title>
<style>{CSS}</style>
</head>
<body>
<div class="container">

<div class="header">
  <div>
    <h1>kx</h1>
    <div class="target">→ {_esc(target)}</div>
    <div class="meta">
      <span>{datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")}</span>
      <span>{js_files_count} JS files</span>
      <span>{len(findings)} findings</span>
    </div>
  </div>
  <div class="actions">
    <button class="btn" id="expand-all">expand all</button>
    <button class="btn" id="collapse-all">collapse all</button>
  </div>
</div>

<div class="sev-grid">
  <div class="tile critical"><div class="label">Critical</div><div class="value {('zero' if not sev_counts.get('critical') else '')}">{sev_counts.get('critical',0)}</div></div>
  <div class="tile high"><div class="label">High</div><div class="value {('zero' if not sev_counts.get('high') else '')}">{sev_counts.get('high',0)}</div></div>
  <div class="tile medium"><div class="label">Medium</div><div class="value {('zero' if not sev_counts.get('medium') else '')}">{sev_counts.get('medium',0)}</div></div>
  <div class="tile low"><div class="label">Low</div><div class="value {('zero' if not sev_counts.get('low') else '')}">{sev_counts.get('low',0)}</div></div>
  <div class="tile total"><div class="label">Total</div><div class="value">{len(findings)}</div></div>
  <div class="tile files"><div class="label">JS files</div><div class="value">{js_files_count}</div></div>
</div>

<div class="toolbar">
  <input type="search" id="search" placeholder="Filter...  (press / to focus)">
  {sev_chips}
  {('<span style="color:var(--fg-dim);font-size:11px;margin:0 4px">·</span>' if cat_chips else '')}
  {cat_chips}
</div>

<section>
  <h2>Triage -- start here <span class="count">{len(triage)} of {sev_counts.get('critical',0)+sev_counts.get('high',0)} high/critical</span></h2>
  {triage_html}
</section>

<section>
  <h2>By file <span class="count">{len(file_urls_sorted)} files</span></h2>
  {files_html}
</section>

{rt_html}

<section>
  <h2>All findings <span class="count">{len(findings)} total</span></h2>
  <table class="all-table" style="width:100%;border-collapse:collapse;font-size:12.5px">
  <thead style="text-align:left;border-bottom:1px solid var(--border)">
    <tr>
      <th style="padding:8px 6px;font-weight:600;color:var(--fg-dim);font-size:11px">SEV</th>
      <th style="padding:8px 6px;font-weight:600;color:var(--fg-dim);font-size:11px">CATEGORY</th>
      <th style="padding:8px 6px;font-weight:600;color:var(--fg-dim);font-size:11px">NAME</th>
      <th style="padding:8px 6px;font-weight:600;color:var(--fg-dim);font-size:11px">MATCH</th>
      <th style="padding:8px 6px;font-weight:600;color:var(--fg-dim);font-size:11px">LINE</th>
      <th style="padding:8px 6px;font-weight:600;color:var(--fg-dim);font-size:11px">FILE</th>
    </tr>
  </thead>
  <tbody>{table_rows}</tbody>
  </table>
</section>

</div>
<script>{JS}</script>
</body></html>"""

    Path(path).write_text(document, encoding="utf-8")
