"""
kx -- Triage HTML Report

Single self-contained .html file laid out as an operator triage view:
top-of-page count chips (real / verify / fp), severity histogram,
clickable tabs to filter by verdict, and per-finding cards with
evidence, rationale, and a suggested action.

The auto_triage module sets `verdict` and `verdict_reason` on every
finding before this runs. Findings without a verdict default to
"verify".

Design choices:
  - All inline CSS / JS. No external deps. Works offline, mailable.
  - Findings grouped by verdict (real → verify → fp), then sorted by
    severity within each group.
  - Per-finding action lines are derived from category -- same logic as
    the REPL's `curl` hints, but rendered as readable instructions.
  - Evidence box shows the structured evidence chain (from semantic
    detectors) plus the raw snippet (collapsed by default).
"""
from __future__ import annotations
import html as _html
import json
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from collections import Counter


# ── action hints by category ───────────────────────────────────────────────
# When the triage card renders, we use this to suggest "what to do next."
# Mirrors the REPL's curl hints but adapted for the HTML context.

def _action_for(f) -> str:
    cat = (f.category or "").lower()
    name = (f.name or "").lower()
    match = (f.match or "").strip()

    if "idor" in cat:
        return ("Change the ID parameter to one belonging to another tenant/user. "
                f"In Burp, replay the request with the <code>{_html.escape(match)}</code> "
                "field set to a sequential or known-other-user value, and check whether the "
                "response leaks data you shouldn't see.")
    if "ssrf" in cat:
        return ("Submit the request with the URL parameter set to "
                "<code>http://169.254.169.254/latest/meta-data/</code> (AWS IMDS) and "
                "<code>http://localhost:[port]</code> to probe internal services. "
                "Check whether the response leaks cloud metadata or internal HTTP responses.")
    if "auth_bypass" in cat or "client-side-only validation" in name:
        return ("The field is validated client-side only. Intercept the request, "
                "remove or weaken the field, and replay -- the server-side check is "
                "likely missing or trusts the client.")
    if "privilege_escalation" in cat or "permission/role field" in name:
        return ("Intercept the request and set the role/permission field to "
                "<code>admin</code>, <code>super-admin</code>, or <code>root</code>. "
                "If the server respects the value, you have privilege escalation.")
    if "admin panel" in name:
        return (f"GET <code>{_html.escape(match)}</code> unauthenticated and with a "
                "low-privilege session cookie. A 200 with content (rather than 302 → /login) "
                "means the server is missing an authorization check.")
    if "s3 bucket" in name:
        return ("Test for public read: <code>curl https://[bucket].s3.amazonaws.com/</code> "
                "and <code>aws s3 ls s3://[bucket] --no-sign-request</code>. Also try public "
                "write with a PUT of a test file.")
    if "redirect" in name and "url" in name:
        return ("Replace the redirect parameter with <code>https://attacker.com</code> "
                "and follow the chain. If the server emits a 302 with a Location header to "
                "the attacker-controlled URL, this is a classic open redirect (phishing / "
                "OAuth token theft chain).")
    if "password field" in name:
        return ("Trace where this field is submitted. Check that it's transmitted over "
                "HTTPS, not logged, and that server-side validation enforces minimum "
                "complexity. Look for password endpoints in the API surface section.")
    if "prototype pollution" in name:
        return ("Inject <code>?__proto__[admin]=true</code> in a query string or "
                "<code>{\"__proto__\":{\"admin\":true}}</code> in a JSON body. Check whether "
                "the polluted property reaches a security check downstream.")
    if "innerhtml" in name or "new function" in name or "document.write" in name:
        return ("Trace what value reaches the sink. If user input flows in without "
                "sanitization, you have client-side XSS. Try injecting "
                "<code>&lt;img src=x onerror=alert(1)&gt;</code> in upstream inputs.")
    if "postmessage" in name:
        return ("Open the target in an iframe from an attacker page, then "
                "<code>window.frames[0].postMessage({...}, '*')</code> with crafted "
                "payloads. The receiver must validate <code>event.origin</code>; if it "
                "doesn't, cross-origin message injection is possible.")
    if "localstorage" in name or "storage_token" in cat:
        return ("Confirm both <code>token</code> and <code>refreshToken</code> live in "
                "localStorage. Any XSS on this origin then exfiltrates persistent auth -- "
                "this finding amplifies the impact of any XSS finding to full account takeover.")
    if "cors" in name:
        return ("Test CORS from an attacker origin. Send a preflight OPTIONS request "
                "and check whether <code>Access-Control-Allow-Origin</code> is reflected.")
    if "jwt" in name:
        return ("Decode the JWT (jwt.io). Check the <code>alg</code> claim -- if HS256 with "
                "a weak secret, try cracking with <code>hashcat -m 16500</code>. Try "
                "<code>alg: none</code>. Check whether the <code>role</code> claim is "
                "respected when modified.")
    return ("Manually verify. Trace the value through the bundle and check for "
            "server-side validation. Use Burp to replay with modified inputs.")


def _severity_rank(sev: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(sev, 0)


def _esc(s: str | None) -> str:
    if s is None:
        return ""
    return _html.escape(str(s))


def _short_file(url: str) -> str:
    if not url:
        return ""
    if url.startswith("sourcemap://"):
        return "[src] " + url.split("#", 1)[1] if "#" in url else url
    return url.rsplit("/", 1)[-1] or url


# ── template ───────────────────────────────────────────────────────────────

def export_triage_html(
    target: str,
    findings: list,
    rt_findings: list,
    js_urls: list[str],
    diff: dict | None,
    path: Path,
) -> None:
    """Render the triage HTML report to disk."""
    # Bucket by verdict
    real    = [f for f in findings if getattr(f, "verdict", "") == "real"]
    verify  = [f for f in findings if getattr(f, "verdict", "") == "verify" or not getattr(f, "verdict", "")]
    fps     = [f for f in findings if getattr(f, "verdict", "") == "fp"]

    # Sort within bucket by severity desc
    for bucket in (real, verify, fps):
        bucket.sort(key=lambda f: (-_severity_rank(f.severity), f.category, f.line or 0))

    host = urlparse(target).netloc or target
    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    # Severity histogram
    sev_counts = Counter(f.severity for f in findings)

    # Build findings JSON for the JS layer
    finding_data = []
    for idx, f in enumerate(findings):
        ev_lines = []
        if f.evidence:
            for ev in f.evidence:
                kind = (ev.get("kind") or "")
                snip = (ev.get("snippet") or "").replace("\n", " ")[:200]
                ev_lines.append(f"{kind}: {snip}")
        finding_data.append({
            "id":             idx,
            "verdict":        getattr(f, "verdict", "verify") or "verify",
            "verdict_reason": getattr(f, "verdict_reason", "") or "",
            "severity":       f.severity,
            "category":       f.category,
            "name":           f.name,
            "match":          f.match or "",
            "file":           _short_file(f.source_url),
            "source_url":     f.source_url or "",
            "line":           f.line or 0,
            "confidence":     f.confidence,
            "note":           getattr(f, "note", "") or "",
            "evidence":       ev_lines,
            "snippet":        (f.snippet or "")[:600],
            "action":         _action_for(f),
        })

    payload_json = json.dumps(finding_data)

    # ── write ──────────────────────────────────────────────────────────
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(_TRIAGE_HTML_TEMPLATE.format(
            target_host       = _esc(host),
            target_url        = _esc(target),
            ts                = ts,
            n_total           = len(findings),
            n_real            = len(real),
            n_verify          = len(verify),
            n_fp              = len(fps),
            n_js              = len(js_urls),
            n_critical        = sev_counts.get("critical", 0),
            n_high            = sev_counts.get("high", 0),
            n_medium          = sev_counts.get("medium", 0),
            n_low             = sev_counts.get("low", 0),
            findings_json     = payload_json,
        ))


_TRIAGE_HTML_TEMPLATE = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>kx triage -- {target_host}</title>
<style>
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
:root {{
  --bg:           #0f0f10;
  --bg-2:         #18181b;
  --bg-3:         #232328;
  --fg:           #e6e6e6;
  --fg-dim:       #a0a0a8;
  --fg-faint:     #6a6a72;
  --border:       #2a2a30;
  --accent:       #7ee48a;
  --critical:     #ff6b6b;
  --high:         #ffa860;
  --medium:       #76c2ff;
  --low:          #b9b9c0;
  --real-bg:      #1e2d18;
  --real-fg:      #98e07c;
  --verify-bg:    #2a253d;
  --verify-fg:    #b09cf5;
  --fp-bg:        #2d2229;
  --fp-fg:        #d785a2;
  --mono:         ui-monospace, "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
}}
body {{
  background: var(--bg);
  color: var(--fg);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Inter, system-ui, sans-serif;
  font-size: 14px;
  line-height: 1.55;
  padding: 28px 36px 60px;
  max-width: 1280px;
  margin: 0 auto;
}}
h1 {{
  font-size: 22px;
  font-weight: 600;
  margin-bottom: 4px;
}}
.subtitle {{
  font-family: var(--mono);
  font-size: 12px;
  color: var(--fg-dim);
  margin-bottom: 22px;
}}
.subtitle a {{ color: var(--accent); text-decoration: none; }}
.subtitle a:hover {{ text-decoration: underline; }}

.chips {{
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
  margin-bottom: 20px;
}}
.chip {{
  font-family: var(--mono);
  font-size: 11px;
  padding: 4px 10px;
  border-radius: 14px;
  border: 1px solid var(--border);
  background: var(--bg-2);
  color: var(--fg-dim);
}}

.stats {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 10px;
  margin-bottom: 24px;
}}
.stat {{
  background: var(--bg-2);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 14px 18px;
}}
.stat-n {{
  font-family: var(--mono);
  font-size: 26px;
  font-weight: 500;
  line-height: 1;
}}
.stat-l {{
  font-family: var(--mono);
  font-size: 10px;
  color: var(--fg-faint);
  text-transform: uppercase;
  letter-spacing: 0.06em;
  margin-top: 6px;
}}
.stat-real .stat-n  {{ color: var(--real-fg); }}
.stat-verify .stat-n{{ color: var(--verify-fg); }}
.stat-fp .stat-n    {{ color: var(--fp-fg); }}

.histo {{
  display: flex;
  gap: 8px;
  align-items: baseline;
  margin-bottom: 22px;
  font-family: var(--mono);
  font-size: 12px;
  color: var(--fg-dim);
}}
.histo-cell {{ display: inline-flex; align-items: center; gap: 4px; }}
.histo-dot {{
  display: inline-block;
  width: 8px;
  height: 8px;
  border-radius: 50%;
}}
.dot-crit   {{ background: var(--critical); }}
.dot-high   {{ background: var(--high); }}
.dot-medium {{ background: var(--medium); }}
.dot-low    {{ background: var(--low); }}

.tabs {{
  display: flex;
  gap: 4px;
  margin-bottom: 16px;
  border-bottom: 1px solid var(--border);
}}
.tab {{
  font-size: 13px;
  font-family: var(--mono);
  padding: 8px 16px;
  cursor: pointer;
  background: none;
  border: 0;
  color: var(--fg-dim);
  border-bottom: 2px solid transparent;
}}
.tab:hover {{ color: var(--fg); }}
.tab.active {{
  color: var(--fg);
  border-bottom-color: var(--accent);
}}
.tab .count {{
  display: inline-block;
  margin-left: 6px;
  font-size: 11px;
  color: var(--fg-faint);
}}

.search-box {{
  margin-bottom: 18px;
}}
.search-box input {{
  width: 100%;
  background: var(--bg-2);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 9px 14px;
  font-family: var(--mono);
  font-size: 13px;
  color: var(--fg);
}}
.search-box input:focus {{ outline: none; border-color: var(--accent); }}

.card {{
  background: var(--bg-2);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 16px 18px;
  margin-bottom: 10px;
  transition: border-color .15s;
}}
.card:hover {{ border-color: #3a3a44; }}
.card-head {{
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 12px;
  margin-bottom: 6px;
}}
.card-title {{
  font-size: 14px;
  font-weight: 500;
  line-height: 1.4;
}}
.card-meta {{
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
  margin-bottom: 10px;
}}
.badge {{
  font-family: var(--mono);
  font-size: 10px;
  padding: 2px 8px;
  border-radius: 10px;
  letter-spacing: 0.02em;
}}
.sev-critical {{ background: rgba(255,107,107,.15); color: var(--critical); }}
.sev-high     {{ background: rgba(255,168,96,.15); color: var(--high); }}
.sev-medium   {{ background: rgba(118,194,255,.15); color: var(--medium); }}
.sev-low      {{ background: rgba(185,185,192,.15); color: var(--low); }}
.sev-info     {{ background: rgba(185,185,192,.10); color: var(--fg-faint); }}
.verdict-real   {{ background: var(--real-bg);   color: var(--real-fg); }}
.verdict-verify {{ background: var(--verify-bg); color: var(--verify-fg); }}
.verdict-fp     {{ background: var(--fp-bg);     color: var(--fp-fg); }}
.cat-badge {{
  background: var(--bg-3);
  color: var(--fg-dim);
}}

.match-line {{
  font-family: var(--mono);
  font-size: 12px;
  color: var(--high);
  background: var(--bg-3);
  padding: 6px 10px;
  border-radius: 5px;
  margin-bottom: 8px;
  word-break: break-all;
}}
.file-line {{
  font-family: var(--mono);
  font-size: 11px;
  color: var(--fg-faint);
  margin-bottom: 10px;
}}
.file-line .fname {{ color: var(--medium); }}

.note {{
  color: var(--fg-dim);
  font-size: 13px;
  margin-bottom: 10px;
}}
.note code {{
  font-family: var(--mono);
  background: var(--bg-3);
  padding: 1px 5px;
  border-radius: 3px;
  font-size: 11.5px;
  color: var(--fg);
}}

.section-lbl {{
  font-family: var(--mono);
  font-size: 10px;
  color: var(--fg-faint);
  text-transform: uppercase;
  letter-spacing: 0.08em;
  margin: 12px 0 4px;
}}

.evidence {{
  font-family: var(--mono);
  font-size: 11.5px;
  background: var(--bg-3);
  border: 1px solid var(--border);
  border-radius: 5px;
  padding: 8px 10px;
  color: var(--fg-dim);
  word-break: break-word;
  white-space: pre-wrap;
  line-height: 1.6;
  margin-bottom: 8px;
}}
.evidence-line {{
  margin: 2px 0;
}}
.evidence-kind {{ color: var(--accent); }}

.action {{
  background: var(--bg-3);
  border-left: 3px solid var(--accent);
  padding: 9px 12px;
  border-radius: 0 5px 5px 0;
  font-size: 12.5px;
  color: var(--fg);
  margin-bottom: 8px;
}}
.action code {{
  font-family: var(--mono);
  background: var(--bg);
  padding: 1px 5px;
  border-radius: 3px;
  font-size: 11px;
  color: var(--accent);
}}

.reason {{
  font-family: var(--mono);
  font-size: 11px;
  color: var(--fg-faint);
  margin-top: 6px;
  padding-top: 6px;
  border-top: 1px dashed var(--border);
}}
.reason-tag {{ color: var(--fg-dim); }}

.empty {{
  padding: 60px 0;
  text-align: center;
  color: var(--fg-faint);
  font-family: var(--mono);
  font-size: 13px;
}}

.snippet-toggle {{
  font-family: var(--mono);
  font-size: 10px;
  color: var(--fg-faint);
  cursor: pointer;
  margin-top: 6px;
  user-select: none;
}}
.snippet-toggle:hover {{ color: var(--accent); }}
.snippet-body {{
  display: none;
  margin-top: 6px;
}}
.snippet-body.open {{ display: block; }}

footer {{
  margin-top: 40px;
  padding-top: 20px;
  border-top: 1px solid var(--border);
  font-family: var(--mono);
  font-size: 11px;
  color: var(--fg-faint);
  text-align: center;
}}
</style>
</head>
<body>

<h1>kx triage -- {target_host}</h1>
<div class="subtitle">
  <a href="{target_url}" target="_blank">{target_url}</a> · {ts} · {n_js} js files · {n_total} findings
</div>

<div class="chips">
  <span class="chip">⌖ {target_host}</span>
  <span class="chip">{ts}</span>
  <span class="chip">{n_js} js files</span>
  <span class="chip">{n_total} findings</span>
</div>

<div class="stats">
  <div class="stat stat-real">
    <div class="stat-n">{n_real}</div>
    <div class="stat-l">real / investigate</div>
  </div>
  <div class="stat stat-verify">
    <div class="stat-n">{n_verify}</div>
    <div class="stat-l">needs verification</div>
  </div>
  <div class="stat stat-fp">
    <div class="stat-n">{n_fp}</div>
    <div class="stat-l">auto-classified fp</div>
  </div>
</div>

<div class="histo">
  <span class="histo-cell"><span class="histo-dot dot-crit"></span>{n_critical} critical</span>
  <span class="histo-cell"><span class="histo-dot dot-high"></span>{n_high} high</span>
  <span class="histo-cell"><span class="histo-dot dot-medium"></span>{n_medium} medium</span>
  <span class="histo-cell"><span class="histo-dot dot-low"></span>{n_low} low</span>
</div>

<div class="tabs">
  <button class="tab active" data-tab="real"   onclick="setTab(this)">✓ real <span class="count">{n_real}</span></button>
  <button class="tab"          data-tab="verify" onclick="setTab(this)">⚠ verify <span class="count">{n_verify}</span></button>
  <button class="tab"          data-tab="fp"     onclick="setTab(this)">✗ false positive <span class="count">{n_fp}</span></button>
  <button class="tab"          data-tab="all"    onclick="setTab(this)">all <span class="count">{n_total}</span></button>
</div>

<div class="search-box">
  <input type="text" id="search" placeholder="search findings (/  to focus) -- match by name, file, match-string, or category" autocomplete="off">
</div>

<div id="list"></div>

<footer>
  generated by kx · auto-triage rules · cards classified by heuristic, verify everything manually before reporting
</footer>

<script>
const FINDINGS = {findings_json};
let activeTab = 'real';
let searchTerm = '';

function severityClass(sev) {{ return 'sev-' + sev; }}
function verdictClass(v) {{ return 'verdict-' + v; }}

function renderCard(f) {{
  const evHtml = f.evidence && f.evidence.length
    ? f.evidence.map(line => {{
        const idx = line.indexOf(':');
        if (idx < 0) return '<div class="evidence-line">' + esc(line) + '</div>';
        const kind = line.slice(0, idx);
        const rest = line.slice(idx + 1);
        return '<div class="evidence-line"><span class="evidence-kind">' + esc(kind) + '</span>:' + esc(rest) + '</div>';
      }}).join('')
    : '';
  return `
    <div class="card" data-verdict="${{f.verdict}}" data-search="${{(f.name + ' ' + f.match + ' ' + f.file + ' ' + f.category + ' ' + f.note).toLowerCase()}}">
      <div class="card-head">
        <div class="card-title">${{esc(f.name)}}</div>
      </div>
      <div class="card-meta">
        <span class="badge ${{severityClass(f.severity)}}">${{f.severity.toUpperCase()}}</span>
        <span class="badge ${{verdictClass(f.verdict)}}">${{f.verdict.toUpperCase()}}</span>
        <span class="badge cat-badge">${{esc(f.category)}}</span>
        <span class="badge cat-badge">conf: ${{esc(f.confidence)}}</span>
      </div>
      <div class="match-line">${{esc(f.match)}}</div>
      <div class="file-line"><span class="fname">${{esc(f.file)}}</span> · L${{f.line}}</div>
      ${{f.note ? `<div class="note">${{f.note}}</div>` : ''}}
      ${{evHtml ? `<div class="section-lbl">evidence chain</div><div class="evidence">${{evHtml}}</div>` : ''}}
      <div class="section-lbl">suggested action</div>
      <div class="action">${{f.action}}</div>
      ${{f.snippet ? `<div class="snippet-toggle" onclick="toggleSnippet(this)">▸ show raw snippet</div><div class="snippet-body"><div class="evidence">${{esc(f.snippet)}}</div></div>` : ''}}
      ${{f.verdict_reason ? `<div class="reason"><span class="reason-tag">auto-triage:</span> ${{esc(f.verdict_reason)}}</div>` : ''}}
    </div>
  `;
}}

function esc(s) {{
  if (s == null) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}}

function render() {{
  const list = document.getElementById('list');
  let items = FINDINGS;
  if (activeTab !== 'all') items = items.filter(f => f.verdict === activeTab);
  if (searchTerm) {{
    const q = searchTerm.toLowerCase();
    items = items.filter(f =>
      (f.name + ' ' + f.match + ' ' + f.file + ' ' + f.category + ' ' + f.note).toLowerCase().includes(q)
    );
  }}
  if (items.length === 0) {{
    list.innerHTML = '<div class="empty">no findings in this view</div>';
    return;
  }}
  list.innerHTML = items.map(renderCard).join('');
}}

function setTab(btn) {{
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  btn.classList.add('active');
  activeTab = btn.dataset.tab;
  render();
}}

function toggleSnippet(el) {{
  const body = el.nextElementSibling;
  body.classList.toggle('open');
  el.textContent = body.classList.contains('open') ? '▾ hide raw snippet' : '▸ show raw snippet';
}}

document.getElementById('search').addEventListener('input', (e) => {{
  searchTerm = e.target.value;
  render();
}});

// `/` focuses search
document.addEventListener('keydown', (e) => {{
  if (e.key === '/' && document.activeElement !== document.getElementById('search')) {{
    e.preventDefault();
    document.getElementById('search').focus();
  }}
}});

render();
</script>
</body>
</html>
"""
