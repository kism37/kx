"""
kx -- Reporter
Rich terminal output + JSON and Markdown export.
"""

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from extractor import Finding, SEVERITY_RANK
from runtime import RuntimeFinding

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False

SEVERITY_COLOR = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "cyan",
    "info":     "dim",
}

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
    "info":     "⚪",
}


console = Console(highlight=False, force_terminal=None) if RICH_AVAILABLE else None


# ─── C2 OPERATOR CHROME ─────────────────────────────────────────────────────
#
# Everything in this section is designed to look like the operator console of
# an offensive ops platform (Cobalt Strike / Sliver / Mythic). The goal:
# every line should read like ops telemetry, not a script's output.
#
# Conventions:
#   [+] ok / hit / acquired
#   [*] info / running
#   [-] no-op / nothing found
#   [!] warning / attention
#   [×] error / fail
#   ►   operator prompt
#
# Color is used sparingly: severity only, plus dim white for chrome.

# Phase-tag indentation alignment
_TAG_W = 9     # width of "[+] CRAWL" cells
_TS_FMT = "%H:%M:%S"

_SCAN_START_TS: float | None = None  # for elapsed timer
_USE_COLOR = True


def _ts() -> str:
    """HH:MM:SS for log lines."""
    import datetime as _dt
    return _dt.datetime.now().strftime(_TS_FMT)


def _elapsed() -> str:
    import time as _time
    if _SCAN_START_TS is None:
        return "00:00"
    s = int(_time.time() - _SCAN_START_TS)
    m, s = divmod(s, 60)
    return f"{m:02d}:{s:02d}"


_BANNER_LINES = [
    r"       ██╗  ██╗    ██╗  ██╗",
    r"       ██║ ██╔╝    ╚██╗██╔╝",
    r"       █████╔╝      ╚███╔╝ ",
    r"       ██╔═██╗      ██╔██╗ ",
    r"       ██║  ██╗    ██╔╝ ██╗",
    r"       ╚═╝  ╚═╝    ╚═╝  ╚═╝",
]

_TAGLINE = "       javascript reconnaissance  ·  v2.0  ·  offensive triage"


def print_banner(target: str, mode_flags: dict, *, config: dict | None = None):
    """C2-style banner: ASCII logo, single dim subtitle, framed session block."""
    import time as _time
    global _SCAN_START_TS
    _SCAN_START_TS = _time.time()

    if not RICH_AVAILABLE:
        for ln in _BANNER_LINES:
            print(ln)
        print(_TAGLINE)
        print(f"  target: {target}")
        return

    console.print()
    for ln in _BANNER_LINES:
        console.print(f"[bright_red]{ln}[/]")
    console.print(f"[dim]{_TAGLINE}[/]")
    console.print()

    # Session block: thin top/bottom rules, key=value rows. Looks like
    # a beacon-info header.
    width = 78
    console.print("  [dim]┌" + "─" * (width - 4) + "┐[/]")

    def _row(k: str, v: str, vstyle: str = "bright_white"):
        line = f"  [dim]│[/] [dim]{k:>10}[/]  [{vstyle}]{v}[/]"
        # pad to width
        pad = width - 4 - 1 - 10 - 2 - len(v)
        line += " " * max(0, pad) + "[dim]│[/]"
        console.print(line)

    _row("session", f"sess-{int(_SCAN_START_TS)%100000:05d}",  "bright_yellow")
    _row("target",  target,  "bright_green")
    _row("started", _ts(),   "bright_white")

    # Mode chips, joined into a single value cell
    chips = []
    if mode_flags.get("ast"):     chips.append(("ast",     "green"))
    if mode_flags.get("runtime"): chips.append(("runtime", "cyan"))
    if mode_flags.get("diff"):    chips.append(("diff",    "yellow"))
    if mode_flags.get("verify"):  chips.append(("verify",  "magenta"))
    if mode_flags.get("burp"):    chips.append(("burp",    "blue"))
    if not chips:
        chips = [("static-only", "dim")]
    # Render each as: bracketed lowercase tag in its color
    mode_str = " ".join(f"[black on bright_{c}] {n} [/]" for n, c in chips)
    plain_mode_str = " ".join(f" {n} " for n, _ in chips)
    pad = width - 4 - 1 - 10 - 2 - len(plain_mode_str)
    console.print(f"  [dim]│[/] [dim]{'modes':>10}[/]  {mode_str}" + " " * max(0, pad) + "[dim]│[/]")

    # Optional tuning row
    if config:
        order = (("depth","depth"), ("concurrency","conc"),
                 ("delay","delay"), ("crawl_limit","crawl-cap"),
                 ("ast_limit","ast-cap"), ("scope","scope"))
        tune_bits = []
        for k, label in order:
            v = config.get(k)
            if v in (None, "", 0):
                continue
            tune_bits.append(f"[dim]{label}=[/][bright_cyan]{v}[/]")
        if tune_bits:
            tune_str = "  ".join(tune_bits)
            plain = "  ".join(f"{label}={config.get(k)}" for k,label in order
                              if config.get(k) not in (None,"",0))
            pad = width - 4 - 1 - 10 - 2 - len(plain)
            console.print(f"  [dim]│[/] [dim]{'tune':>10}[/]  {tune_str}" + " " * max(0, pad) + "[dim]│[/]")

    console.print("  [dim]└" + "─" * (width - 4) + "┘[/]")
    console.print()


# ── status lines ───────────────────────────────────────────────────────────
#
# Every progress line looks like an ops log entry:
#
#     [HH:MM:SS] [+] CRAWL    crawled 838 resources · 835 js files
#
# Phase tag is colored by phase, status marker by outcome.

_PHASE_COLOR = {
    "crawl":    "cyan",
    "static":   "yellow",
    "ast":      "green",
    "semantic": "magenta",
    "verify":   "magenta",
    "diff":     "blue",
    "report":   "white",
    "info":     "white",
    "warn":     "yellow",
    "error":    "red",
}


def _status_line(marker: str, marker_color: str, phase: str, msg: str):
    if not RICH_AVAILABLE:
        print(f"[{_ts()}] {marker} {phase.upper():<8} {msg}")
        return
    pc = _PHASE_COLOR.get(phase, "white")
    phase_tag = phase.upper().ljust(8)
    console.print(
        f"[dim][{_ts()}][/] "
        f"[{marker_color}]{marker}[/] "
        f"[{pc}]{phase_tag}[/]  {msg}"
    )


def print_progress(msg: str, phase: str = "info"):
    """Standard `[*]` info line. Used during normal execution."""
    _status_line("[*]", "bright_white", phase, msg)

def print_ok(msg: str, phase: str = "info"):
    """`[+]` success line. Use when an action completes with a result."""
    _status_line("[+]", "bright_green", phase, msg)

def print_warn(msg: str, phase: str = "warn"):
    """`[!]` warning line. Yellow."""
    _status_line("[!]", "bright_yellow", phase, msg)

def print_fail(msg: str, phase: str = "error"):
    """`[×]` error line. Red."""
    _status_line("[×]", "bright_red", phase, msg)

def print_neg(msg: str, phase: str = "info"):
    """`[-]` neutral / no-op / nothing-found line. Dim."""
    _status_line("[-]", "dim", phase, msg)


# ── section dividers ───────────────────────────────────────────────────────


def print_section(title: str, *, count: int | None = None, color: str = "bright_white"):
    """
    Heavy section divider -- used to break the output into ops-report
    sections like 'TARGETS', 'FINDINGS', 'POST-EX'.

      ═══ FINDINGS ═══════════════════════════════════════════════ 732 ═══
    """
    if not RICH_AVAILABLE:
        c = f" {count}" if count is not None else ""
        print(f"\n=== {title.upper()} ==={c}\n")
        return

    width = 78
    title_str = f" {title.upper()} "
    count_str = f" {count} " if count is not None else ""

    # Layout: "  " + "═══" + title + fill_rule + count + "═══"
    left_pad = 2
    left_rule = "═══"
    right_rule = "═══"
    content_w = width - left_pad - len(left_rule) - len(title_str) - len(count_str) - len(right_rule)
    fill = "═" * max(3, content_w)

    console.print()
    parts = [
        " " * left_pad,
        f"[dim]{left_rule}[/]",
        f"[bold {color}]{title_str}[/]",
        f"[dim]{fill}[/]",
    ]
    if count_str:
        parts.append(f"[bright_yellow]{count_str}[/]")
    parts.append(f"[dim]{right_rule}[/]")
    console.print("".join(parts))
    console.print()


def print_subsection(title: str, *, count: int | None = None):
    """Lighter divider for nested groups (per-phase or per-category)."""
    if not RICH_AVAILABLE:
        c = f" ({count})" if count is not None else ""
        print(f"\n-- {title} --{c}")
        return
    c = f"  [dim]({count})[/]" if count is not None else ""
    console.print(f"\n  [dim]┄┄┄[/] [bold]{title}[/]{c}  [dim]┄┄┄┄┄┄┄┄┄┄┄[/]")


# ── findings: dossier-style records ────────────────────────────────────────


def _sev_block(sev: str) -> str:
    """Severity rendered as a colored solid block, ops-table style."""
    color_map = {
        "critical": "bright_red",
        "high":     "red",
        "medium":   "bright_yellow",
        "low":      "cyan",
        "info":     "dim",
    }
    label = sev.upper().ljust(8)
    color = color_map.get(sev, "white")
    return f"[black on {color}] {label}[/]"


def _short_url_for_cli(url: str, max_len: int = 48) -> str:
    if url.startswith("sourcemap://"):
        path = url.split("#", 1)[1] if "#" in url else url
        prefix = "[src] "
        if len(prefix) + len(path) <= max_len:
            return prefix + path
        return prefix + "..." + path[-(max_len - len(prefix) - 1):]
    if len(url) <= max_len:
        return url
    return "..." + url[-(max_len - 1):]


def _dedup_findings(findings):
    """
    Collapse findings that repeat the same (category, name, match) across
    many files into a single representative + sibling count.

    On a real-world Vue/Next bundle this collapses noise like 300+ identical
    SVG-path strings into one line that says "× 47 files".
    """
    from collections import defaultdict
    groups: dict[tuple, list] = defaultdict(list)
    for f in findings:
        key = (f.category, f.name, (f.match or "")[:120])
        groups[key].append(f)

    out = []
    for grp in groups.values():
        rep = sorted(
            grp, key=lambda x: (-SEVERITY_RANK.get(x.severity, 0), x.line or 0)
        )[0]
        files = len({f.source_url for f in grp})
        out.append((rep, len(grp), files))

    out.sort(key=lambda t: (
        -SEVERITY_RANK.get(t[0].severity, 0),
        0 if t[0].category.startswith("semantic:") else 1,
        t[0].name,
    ))
    return out


def print_findings(
    findings,
    diff_new: set[str] | None = None,
    *,
    show_all: bool = False,
    top: int | None = None,
):
    """
    C2-style findings output.

    Layout per finding (dossier record):

        [SEV  ]  category::name
                 ► match-string
                 file:line · conf · ×N files

    Semantic findings expand below with their evidence chain.
    Repeated identical findings across many files collapse into a single
    record with a `× N files` count, unless `show_all=True`.
    """
    if not findings:
        if RICH_AVAILABLE:
            console.print("  [dim][-] INFO     no findings.[/]")
        else:
            print("  [-] INFO     no findings.")
        return

    if not RICH_AVAILABLE:
        for f in findings:
            print(f"  [{f.severity.upper():<8}] {f.name} | {f.match[:80]} | {f.source_url}")
        return

    # Group and rank
    if show_all:
        items = [(f, 1, 1) for f in sorted(
            findings,
            key=lambda x: (-SEVERITY_RANK.get(x.severity, 0),
                           0 if x.category.startswith("semantic:") else 1,
                           x.name)
        )]
    else:
        items = _dedup_findings(findings)

    # ── Adaptive per-tier cap ──────────────────────────────────────────
    # On big SPAs you get 300+ LOW records (svg paths, route strings) that
    # drown out the actionable ones. By default we keep all critical/high
    # records, cap medium at 25, cap low at 10. `--top N` sets the cap to
    # the same N across all tiers. `--show-all` disables all capping.
    tier_caps = {"critical": None, "high": None, "medium": 25, "low": 10, "info": 5}
    if top is not None:
        tier_caps = {k: top for k in tier_caps}
    if show_all:
        tier_caps = {k: None for k in tier_caps}

    capped: list = []
    hidden_by_sev: dict[str, int] = {}
    sev_buckets: dict[str, list] = {}
    for trip in items:
        sev_buckets.setdefault(trip[0].severity, []).append(trip)
    for sev in ("critical", "high", "medium", "low", "info"):
        bucket = sev_buckets.get(sev, [])
        cap = tier_caps.get(sev)
        if cap is not None and len(bucket) > cap:
            capped.extend(bucket[:cap])
            hidden_by_sev[sev] = len(bucket) - cap
        else:
            capped.extend(bucket)
    items = capped
    # Legacy single-truncated banner kept for back-compat when --top is set
    truncated = sum(hidden_by_sev.values())

    # Group by severity for visual breaks
    last_sev = None
    rendered = 0
    for rep, count, files in items:
        if rep.severity != last_sev:
            # Severity-group divider, ops-style with count
            sev_findings = [t for t in items if t[0].severity == rep.severity]
            tot_count = sum(t[1] for t in sev_findings)
            color = {
                "critical": "bright_red",
                "high":     "red",
                "medium":   "bright_yellow",
                "low":      "cyan",
                "info":     "dim",
            }.get(rep.severity, "white")
            console.print()
            console.print(
                f"  [{color}]●[/] [bold {color}]{rep.severity.upper()}[/]"
                f"  [dim]·[/]  [bright_white]{len(sev_findings)}[/] [dim]record(s)"
                + (f", {tot_count} total" if tot_count != len(sev_findings) else "")
                + "[/]"
            )
            console.print("  [dim]" + "─" * 74 + "[/]")
            last_sev = rep.severity

        is_new   = diff_new and rep.source_url in diff_new
        is_sem   = rep.category.startswith("semantic:")
        new_tag  = " [black on bright_green] NEW [/]" if is_new else ""
        sem_tag  = " [black on bright_magenta] SEM [/]" if is_sem else ""
        rep_tag  = (f"  [dim]×{count} ({files} files)[/]" if count > 1 else "")

        # Line 1: SEV block + category::name
        console.print(
            f"  {_sev_block(rep.severity)}  "
            f"[dim]{rep.category}[/]  "
            f"[bold]{rep.name}[/]"
            f"{sem_tag}{new_tag}{rep_tag}"
        )

        # Line 2: target match string
        match = (rep.match or "")[:90]
        console.print(f"            [dim]►[/] [bright_yellow]{match}[/]")

        # Line 3: file:line · conf
        file_s = _short_url_for_cli(rep.source_url, 48)
        console.print(
            f"            [dim]at[/] [cyan]{file_s}[/][dim]:[/][bright_cyan]L{rep.line or '?'}[/]"
            f"  [dim]·[/]  [dim]{rep.confidence}[/]"
        )

        # Semantic note + evidence chain inlined for high/critical
        if is_sem and rep.severity in ("critical", "high"):
            if rep.note:
                # Wrap note to ~70 cols, indented
                from textwrap import wrap
                for ln in wrap(rep.note, width=68):
                    console.print(f"            [dim white]{ln}[/]")
            if rep.evidence:
                for ev in rep.evidence:
                    kind = ev.get("kind", "?")[:22]
                    raw_snip = (ev.get("snippet") or "").strip()
                    # Hard cap to keep one record per terminal line. Minified
                    # blobs are unreadable past ~80 cols anyway.
                    if len(raw_snip) > 80:
                        raw_snip = raw_snip[:77] + "..."
                    # Strip newlines so the snippet stays single-line.
                    raw_snip = raw_snip.replace("\n", " ").replace("\r", " ")
                    console.print(
                        f"            [dim]│[/] [bright_black]{kind:<22}[/] [dim]{raw_snip}[/]"
                    )
        console.print()
        rendered += 1

    if truncated:
        bits = []
        for s in ("critical", "high", "medium", "low", "info"):
            n = hidden_by_sev.get(s, 0)
            if n:
                color = {"critical":"bright_red","high":"red","medium":"bright_yellow",
                         "low":"cyan","info":"dim"}.get(s, "white")
                bits.append(f"[{color}]{n} {s}[/]")
        details = " · ".join(bits) if bits else f"{truncated} record(s)"
        print_neg(
            f"... {details} hidden  ([dim]kx ►[/] [bright_green]show low[/][dim] · [/]"
            f"[dim]--show-all to print everything[/])",
            phase="report",
        )


# ── attack surface auto-grouped panels ────────────────────────────────────


def print_attack_surface(findings):
    """
    Auto-extract and present interesting attack-surface groupings from the
    findings.  Each group renders as a compact bullet list.  Sections:

      • Backends (cross-origin hosts referenced)
      • Admin endpoints
      • Auth / login paths
      • Files handling passwords / tokens
      • postMessage / WebSocket / eval sinks
    """
    if not RICH_AVAILABLE:
        return
    from urllib.parse import urlparse
    from collections import defaultdict, Counter

    target_host = ""
    for f in findings:
        if f.source_url and "://" in f.source_url:
            target_host = urlparse(f.source_url).netloc
            break

    # Discovered backends
    backends = Counter()
    for f in findings:
        if f.category in ("endpoints", "ast:endpoint") and f.match.startswith("http"):
            netloc = urlparse(f.match).netloc
            if netloc and netloc != target_host:
                backends[f"{urlparse(f.match).scheme}://{netloc}"] += 1

    # Admin endpoints
    admin = sorted({
        f.match for f in findings
        if f.category in ("endpoints", "ast:endpoint")
        and (f.match.startswith("/admin") or "/admin/" in f.match or f.match.startswith("/control-panel"))
    })[:20]

    # Auth/login routes
    auth = sorted({
        f.match for f in findings
        if f.category in ("endpoints", "ast:endpoint")
        and any(p in f.match for p in ("/login", "/sso", "/password", "/reset", "/auth", "/oauth"))
    })[:15]

    # Files handling passwords/tokens
    pw_files = defaultdict(set)
    for f in findings:
        if (f.category.endswith("sensitive_field") or "password" in (f.name or "").lower()
                or "token" in (f.name or "").lower()):
            pw_files[f.source_url].add(f.match)

    # Dangerous sinks
    sinks = []
    for f in findings:
        if f.category in ("sinks", "ast:sink") and f.severity in ("critical", "high"):
            sinks.append((f.name, _short_url_for_cli(f.source_url, 42), f.line))

    has_any = backends or admin or auth or pw_files or sinks
    if not has_any:
        return

    print_section("ATTACK SURFACE", color="bright_green")

    if backends:
        print_subsection("backends", count=len(backends))
        for host, n in backends.most_common(10):
            console.print(f"    [dim]►[/] [bright_yellow]{host}[/]  [dim]×{n}[/]")

    if admin:
        print_subsection("admin endpoints", count=len(admin))
        for path in admin[:12]:
            console.print(f"    [dim]►[/] [bright_red]{path}[/]")
        if len(admin) > 12:
            console.print(f"    [dim]... {len(admin)-12} more[/]")

    if auth:
        print_subsection("auth / login surface", count=len(auth))
        for path in auth[:10]:
            console.print(f"    [dim]►[/] [bright_magenta]{path}[/]")

    if pw_files:
        print_subsection("password/token handling", count=len(pw_files))
        for url in list(pw_files.keys())[:8]:
            fields = ", ".join(sorted(pw_files[url])[:3])
            console.print(
                f"    [dim]►[/] [cyan]{_short_url_for_cli(url, 50)}[/]  "
                f"[dim]({fields})[/]"
            )

    if sinks:
        print_subsection("dangerous sinks (high/crit)", count=len(sinks))
        for name, file, line in sinks[:10]:
            console.print(
                f"    [dim]►[/] [bright_red]{name}[/]  [dim]at[/] [cyan]{file}[/][dim]:[/][bright_cyan]L{line or '?'}[/]"
            )


# ── runtime captures ──────────────────────────────────────────────────────


def print_runtime_findings(rt_findings):
    if not rt_findings:
        return
    if not RICH_AVAILABLE:
        for r in rt_findings:
            print(f"  [RUNTIME] {r.type.upper()} {r.method} {r.url}")
        return

    print_section("RUNTIME CAPTURE", count=len(rt_findings), color="cyan")
    for r in rt_findings:
        console.print(
            f"    [dim]►[/] [bright_cyan]{r.type.upper():<6}[/] "
            f"[bold]{r.method:<6}[/] [yellow]{r.url}[/]"
        )


# ── diff summary ──────────────────────────────────────────────────────────


def print_diff_summary(diff: dict):
    if not RICH_AVAILABLE:
        print(f"  [DIFF] New: {len(diff['new_findings'])} | Files: +{len(diff['new_js_files'])} -{len(diff.get('removed_js_files',[]))}")
        return
    new_f = len(diff["new_findings"])
    new_j = len(diff["new_js_files"])
    rem_j = len(diff.get("removed_js_files", []))

    color = "bright_yellow" if (new_f or new_j) else "bright_green"
    marker = "[!]" if (new_f or new_j) else "[+]"
    _status_line(marker, color, "diff",
        f"[bright_white]{new_f}[/] new finding(s)  "
        f"[dim]·[/]  [bright_white]+{new_j}[/]/[bright_white]-{rem_j}[/] js files"
    )

    if diff["new_js_files"]:
        for u in diff["new_js_files"][:8]:
            console.print(f"            [bright_green]+[/] [cyan]{_short_url_for_cli(u, 60)}[/]")
        if len(diff["new_js_files"]) > 8:
            console.print(f"            [dim]... +{len(diff['new_js_files']) - 8} more[/]")


# ── final summary block ───────────────────────────────────────────────────


def print_summary(target: str, js_count: int, findings, elapsed: float):
    by_sev = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    if not RICH_AVAILABLE:
        print(f"\n  [SCAN COMPLETE] {target} · {js_count} js · {len(findings)} findings · {elapsed:.1f}s")
        return

    width = 78
    console.print()
    console.print("  [dim]┌" + "─" * (width - 4) + "┐[/]")
    title = " SCAN COMPLETE "
    pad = (width - 4 - len(title)) // 2
    console.print("  [dim]│[/]" + " " * pad +
                  f"[bold bright_green]{title}[/]" +
                  " " * (width - 4 - pad - len(title)) + "[dim]│[/]")
    console.print("  [dim]├" + "─" * (width - 4) + "┤[/]")

    def _row(k, v, color="bright_white"):
        line_v = str(v)
        line = f"  [dim]│[/] [dim]{k:>12}[/]  [{color}]{line_v}[/]"
        pad = width - 4 - 1 - 12 - 2 - len(line_v)
        line += " " * max(0, pad) + "[dim]│[/]"
        console.print(line)

    _row("target",   target,                              "bright_green")
    _row("js files", f"{js_count}",                       "bright_white")
    _row("findings", f"{len(findings)}",                  "bright_white")
    _row("elapsed",  f"{elapsed:.1f}s",                   "bright_white")

    # Severity bar chart
    console.print("  [dim]├" + "─" * (width - 4) + "┤[/]")
    sev_order = ["critical", "high", "medium", "low", "info"]
    sev_colors = {
        "critical": "bright_red", "high": "red", "medium": "bright_yellow",
        "low": "cyan", "info": "dim",
    }
    max_count = max((by_sev.get(s, 0) for s in sev_order), default=0) or 1
    bar_w = width - 4 - 1 - 12 - 2 - 8   # leave room for label + count
    for s in sev_order:
        n = by_sev.get(s, 0)
        if n == 0 and s == "info":
            continue
        bar_len = int((n / max_count) * bar_w) if max_count else 0
        bar = "█" * bar_len
        color = sev_colors.get(s, "white")
        count_str = f"{n:>4}"
        bar_render = f"[{color}]{bar}[/]" if bar else "[dim]·[/]"
        line = f"  [dim]│[/] [dim]{s.upper():>12}[/]  [bright_white]{count_str}[/] {bar_render}"
        # Compute padding from plain content
        plain = f"  │ {s.upper():>12}  {count_str} {'█'*bar_len if bar_len else '·'}"
        pad = width - len(plain)
        line += " " * max(0, pad - 1) + "[dim]│[/]"
        console.print(line)

    console.print("  [dim]└" + "─" * (width - 4) + "┘[/]")


# ── operator prompt (post-scan call-to-action) ────────────────────────────


def print_operator_prompt(reports: dict):
    """
    Print a 'next moves' prompt block listing the artifacts the operator
    can now act on. Each entry rendered like a C2 menu option.
    """
    if not RICH_AVAILABLE:
        for k, v in reports.items():
            print(f"  > {k}: {v}")
        return

    console.print()
    console.print("  [bold bright_green]kx[/][bright_green] ►[/] [dim]artifacts ready[/]")
    for label, path in reports.items():
        console.print(f"    [dim][[/][bright_yellow]+[/][dim]][/] [bold]{label:<10}[/] [cyan]{path}[/]")
    console.print()


# ── live phase progress ───────────────────────────────────────────────────
#
# Long phases (AST over 40+ files, sourcemap recovery, LLM verification)
# would otherwise sit silent for many seconds. We render a single
# `\r`-updated status line:
#
#   [05:08:59] [*] AST   running ····· 23/40 files · last: app-BOJ6Yb6P.js
#
# After completion, the live line is REPLACED with a static `[+]` line so
# the scrollback log stays clean.

class LiveTracker:
    """
    Single-line in-place progress for a phase. Use as a context manager:

        with LiveTracker(phase="ast", total=40, label="running AST") as live:
            for ... :
                live.tick(last="app-BOJ6Yb6P.js")
            live.done("AST done: 638 finding(s) from 40 file(s)")

    If rich is unavailable, falls back to a single print of the start line.
    """
    def __init__(self, phase: str, total: int, label: str):
        self.phase = phase
        self.total = total
        self.label = label
        self.n     = 0
        self.last  = ""
        self._live = None
        self._final_msg = None

    def __enter__(self):
        if not RICH_AVAILABLE or self.total <= 0:
            print_progress(self.label, phase=self.phase)
            return self
        from rich.live import Live
        self._live = Live(
            self._render(),
            console=console,
            refresh_per_second=10,
            transient=True,         # the live line is wiped on exit
        )
        self._live.__enter__()
        return self

    def _render(self):
        from rich.text import Text
        # Replicate the standard status-line format exactly so the live
        # row visually matches the surrounding log.
        pc = _PHASE_COLOR.get(self.phase, "white")
        phase_tag = self.phase.upper().ljust(8)
        # progress bar
        filled = int((self.n / self.total) * 24) if self.total else 0
        bar = "█" * filled + "░" * (24 - filled)
        pct = int((self.n / self.total) * 100) if self.total else 0
        last_part = f" · last: [bright_black]{self.last[-46:]}[/]" if self.last else ""
        return Text.from_markup(
            f"  [dim][{_ts()}][/] [bright_white][*][/] "
            f"[{pc}]{phase_tag}[/]  {self.label}  "
            f"[{pc}]{bar}[/] [bright_white]{self.n:>3}[/]/[bright_white]{self.total}[/] "
            f"[dim]({pct}%)[/]{last_part}"
        )

    def tick(self, last: str = None):
        self.n += 1
        if last:
            self.last = last
        if self._live:
            self._live.update(self._render())

    def done(self, final_msg: str):
        self._final_msg = final_msg

    def __exit__(self, *exc):
        if self._live:
            self._live.__exit__(*exc)
        if self._final_msg:
            print_ok(self._final_msg, phase=self.phase)


# ── export ─────────────────────────────────────────────────────────────────


def export_json(
    target: str,
    findings: list[Finding],
    rt_findings: list,
    diff: dict | None,
    path: Path,
):
    out = {
        "kx_version": "2.0.0",
        "target": target,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "finding_count": len(findings),
        "findings": [f.to_dict() for f in findings],
        "runtime_requests": [
            {"type": r.type, "url": r.url, "method": r.method}
            for r in rt_findings
        ],
    }
    if diff:
        out["diff"] = {
            "is_first_scan": diff.get("is_first_scan", True),
            "new_finding_count": len(diff.get("new_findings", [])),
            "new_js_files": diff.get("new_js_files", []),
            "removed_js_files": diff.get("removed_js_files", []),
        }
    path.write_text(json.dumps(out, indent=2))


def export_markdown(
    target: str,
    findings: list[Finding],
    rt_findings: list,
    path: Path,
):
    lines = [
        f"# kx Report -- {target}",
        f"",
        f"> Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}  ",
        f"> Total findings: {len(findings)}",
        f"",
        f"---",
        f"",
        f"## Findings",
        f"",
        f"| Severity | Category | Name | Match | Line | Source |",
        f"|----------|----------|------|-------|------|--------|",
    ]

    for f in findings:
        match_safe = f.match[:60].replace("|", "\\|")
        url_short = _short_url(f.source_url)
        lines.append(
            f"| {f.severity.upper()} | {f.category} | {f.name} | `{match_safe}` | {f.line} | {url_short} |"
        )

    # Detailed evidence sections for semantic findings (high/critical only)
    sem = [f for f in findings if f.category.startswith("semantic:")
           and f.severity in ("critical", "high")]
    if sem:
        lines += [
            "",
            "## Semantic findings -- evidence chains",
            "",
        ]
        for f in sem:
            lines += [
                f"### [{f.severity.upper()}] {f.name}",
                f"",
                f"- **Target:** `{f.match}`",
                f"- **Source:** {f.source_url}:{f.line}",
                f"",
            ]
            if f.note:
                lines += [f"{f.note}", ""]
            if f.evidence:
                lines.append("**Evidence:**")
                lines.append("")
                for ev in f.evidence:
                    kind = ev.get("kind", "?")
                    snip = (ev.get("snippet") or "").replace("\n", " ")[:280]
                    ln = ev.get("line", "")
                    lines.append(f"- `{kind}` (line {ln}): `{snip}`")
                lines.append("")

    if rt_findings:
        lines += [
            "",
            "## Runtime Captured Requests",
            "",
            "| Type | Method | URL |",
            "|------|--------|-----|",
        ]
        for r in rt_findings:
            lines.append(f"| {r.type} | {r.method} | {r.url} |")

    lines += ["", "---", "_Generated by kx_", ""]
    path.write_text("\n".join(lines))


# ── helpers ────────────────────────────────────────────────────────────────


def _short_url(url: str, max_len: int = 50) -> str:
    # Recovered-from-sourcemap virtual URLs: render as the original path
    # with a [src] tag so it's instantly recognisable in reports.
    if url.startswith("sourcemap://"):
        # Format: sourcemap://<map-url>#<original-path>
        if "#" in url:
            path = url.split("#", 1)[1]
            display = f"[src] {path}"
            if len(display) <= max_len:
                return display
            return "[src] ..." + path[-(max_len - 8):]
    if len(url) <= max_len:
        return url
    return "..." + url[-(max_len - 1):]


# ── HTML export ────────────────────────────────────────────────────────────
#
# Faithful port of v1's HTML reporter with three additions for v2's
# semantic findings:
#   1. Triage block at the top -- the 5 highest-priority semantic findings
#      with their evidence chain expanded by default.
#   2. Evidence chains rendered in the detail panel for any finding that
#      carries them.
#   3. The hunter-readable `note` field shown above the snippet when present.
#
# Everything else (severity tiles, filter buttons, layout, JS structure)
# is preserved so the look of v1 HTML reports -- which you already use -- is
# consistent.

def export_html(
    target: str,
    findings: list[Finding],
    rt_findings: list,
    js_urls: list[str],
    diff: dict | None,
    path: Path,
) -> None:
    from urllib.parse import urlparse

    # ── derived data (same as v1) ─────────────────────────────────────────
    backends = sorted({
        f"{urlparse(f.match).scheme}://{urlparse(f.match).netloc}"
        for f in findings
        if f.category in ("endpoints", "ast:endpoint")
        and f.match.startswith("http")
        and urlparse(f.match).netloc
        and urlparse(f.match).netloc != urlparse(target).netloc
    })
    admin_paths = sorted({
        f.match for f in findings
        if f.category in ("endpoints", "ast:endpoint")
        and f.match.startswith("/v1/admin")
    })

    ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1

    # ── pick triage (v2 addition) ─────────────────────────────────────────
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    triage = sorted(
        [f for f in findings
         if f.category.startswith("semantic:")
         and f.severity in ("critical", "high")],
        key=lambda f: (-sev_rank.get(f.severity, 0),
                       0 if (f.note or f.evidence) else 1),
    )[:5]
    triage_ids = {id(f) for f in triage}

    # Serialize findings for the client-side filter
    def _finding_to_dict(f: Finding) -> dict:
        d = f.to_dict()
        # to_dict() may already include these; ensure they're there for the JS.
        d.setdefault("note", getattr(f, "note", "") or "")
        d.setdefault("evidence", getattr(f, "evidence", []) or [])
        return d

    findings_json = json.dumps([_finding_to_dict(f) for f in findings])
    triage_json = json.dumps([_finding_to_dict(f) for f in triage])
    rt_json       = json.dumps([{"type": r.type, "url": r.url, "method": r.method}
                                for r in rt_findings])
    backends_json = json.dumps(backends)
    admin_json    = json.dumps(admin_paths)
    js_json       = json.dumps(js_urls[:200])

    # Triage tile only appears if there's at least one triage finding
    triage_section_attr = "" if triage else ' style="display:none"'

    # Build the HTML. The structure mirrors v1 verbatim, with the
    # `triage-section`, `evidence`, and `note` additions wired in.
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>kx -- {target}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
:root{{
  --bg:#0d0d0d;--bg2:#141414;--bg3:#1a1a1a;--bg4:#222;
  --border:#2a2a2a;--border2:#333;
  --text:#e8e8e8;--text2:#999;--text3:#555;
  --green:#22c55e;--yellow:#eab308;--red:#ef4444;--blue:#3b82f6;--cyan:#06b6d4;--orange:#f97316;
  --crit:#ef4444;--high:#f97316;--med:#3b82f6;--low:#6b7280;
  --font-mono:'JetBrains Mono','Fira Code','Cascadia Code',monospace;
  --font-sans:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
  --radius:6px;--radius-lg:10px;
}}
body{{background:var(--bg);color:var(--text);font-family:var(--font-sans);font-size:14px;line-height:1.6;min-height:100vh}}
a{{color:var(--cyan);text-decoration:none}}
.mono{{font-family:var(--font-mono);font-size:12px}}
.layout{{max-width:1100px;margin:0 auto;padding:2rem 1.5rem}}

.header{{margin-bottom:2rem}}
.logo{{font-family:var(--font-mono);font-size:28px;font-weight:700;color:var(--green);letter-spacing:-.03em}}
.target{{font-family:var(--font-mono);font-size:13px;color:var(--text2);margin-top:4px}}
.meta{{display:flex;gap:8px;margin-top:10px;flex-wrap:wrap}}
.chip{{display:inline-flex;align-items:center;gap:4px;font-family:var(--font-mono);font-size:11px;padding:3px 9px;border-radius:var(--radius);border:1px solid var(--border2);color:var(--text2);background:var(--bg3)}}

.metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:10px;margin-bottom:2rem}}
.metric{{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius-lg);padding:14px 16px}}
.metric-label{{font-size:11px;color:var(--text3);font-family:var(--font-mono);margin-bottom:4px;text-transform:uppercase;letter-spacing:.05em}}
.metric-val{{font-size:26px;font-weight:700;font-family:var(--font-mono)}}
.metric-val.crit{{color:var(--crit)}}
.metric-val.high{{color:var(--high)}}
.metric-val.med{{color:var(--med)}}
.metric-val.low{{color:var(--low)}}
.metric-val.total{{color:var(--text)}}

.section{{background:var(--bg2);border:1px solid var(--border);border-radius:var(--radius-lg);margin-bottom:1.5rem;overflow:hidden}}
.section-header{{display:flex;align-items:center;justify-content:space-between;padding:12px 16px;border-bottom:1px solid var(--border);background:var(--bg3)}}
.section-title{{font-family:var(--font-mono);font-size:12px;font-weight:600;color:var(--text2);text-transform:uppercase;letter-spacing:.08em}}
.section-title .sub{{color:var(--text3);font-weight:400;margin-left:8px}}

/* triage cards -- v2 addition */
.triage-list{{padding:12px 16px;display:flex;flex-direction:column;gap:10px}}
.triage-card{{background:var(--bg3);border:1px solid var(--border2);border-left:3px solid var(--high);border-radius:var(--radius);padding:12px 14px}}
.triage-card.critical{{border-left-color:var(--crit)}}
.triage-card.high{{border-left-color:var(--high)}}
.triage-row{{display:flex;align-items:baseline;gap:10px;flex-wrap:wrap;margin-bottom:6px}}
.triage-name{{font-size:13px;font-weight:600;color:var(--text)}}
.triage-match{{font-family:var(--font-mono);font-size:11px;color:var(--high);background:rgba(249,115,22,.08);padding:1px 7px;border-radius:4px;word-break:break-all}}
.triage-card.critical .triage-match{{color:var(--crit);background:rgba(239,68,68,.08)}}
.triage-loc{{font-family:var(--font-mono);font-size:10px;color:var(--text3);margin-left:auto;flex-shrink:0}}
.triage-note{{font-size:12.5px;color:var(--text);margin:6px 0 0 0;line-height:1.6}}

/* note block -- v2 addition */
.note{{font-size:12px;color:var(--text);background:rgba(59,130,246,.06);border-left:2px solid var(--med);padding:8px 12px;border-radius:4px;margin:8px 0;line-height:1.55}}

/* evidence chain -- v2 addition */
.evidence{{margin-top:8px;padding:8px 12px;background:var(--bg);border:1px solid var(--border);border-radius:4px;font-family:var(--font-mono);font-size:11px}}
.ev-row{{display:flex;gap:10px;padding:2px 0;align-items:flex-start}}
.ev-kind{{color:var(--text3);min-width:130px;flex-shrink:0;font-weight:600}}
.ev-snip{{color:var(--text2);word-break:break-all;flex:1;line-height:1.55}}
.ev-snip .ln{{color:var(--text3);margin-right:6px}}

.filters{{display:flex;gap:6px;padding:12px 16px;border-bottom:1px solid var(--border);flex-wrap:wrap}}
.filter-btn{{font-family:var(--font-mono);font-size:11px;padding:4px 10px;border-radius:var(--radius);border:1px solid var(--border2);background:none;color:var(--text2);cursor:pointer;transition:all .15s}}
.filter-btn:hover{{background:var(--bg3);color:var(--text)}}
.filter-btn.active{{background:var(--green);color:#000;border-color:var(--green);font-weight:600}}

.search-row{{padding:10px 16px;border-bottom:1px solid var(--border)}}
.search-row input{{width:100%;background:var(--bg);border:1px solid var(--border2);border-radius:var(--radius);color:var(--text);font-family:inherit;font-size:13px;padding:6px 12px}}
.search-row input:focus{{outline:none;border-color:var(--green)}}

.finding{{border-bottom:1px solid var(--border);cursor:pointer;transition:background .1s}}
.finding:last-child{{border-bottom:none}}
.finding:hover .finding-row{{background:var(--bg3)}}
.finding-row{{display:grid;grid-template-columns:80px 140px 1fr 55px;gap:12px;align-items:center;padding:10px 16px}}
.sev-badge{{font-family:var(--font-mono);font-size:10px;font-weight:700;padding:2px 7px;border-radius:4px;text-transform:uppercase;letter-spacing:.05em;text-align:center}}
.sev-critical{{background:rgba(239,68,68,.15);color:var(--crit);border:1px solid rgba(239,68,68,.3)}}
.sev-high{{background:rgba(249,115,22,.15);color:var(--high);border:1px solid rgba(249,115,22,.3)}}
.sev-medium{{background:rgba(59,130,246,.15);color:var(--med);border:1px solid rgba(59,130,246,.3)}}
.sev-low{{background:rgba(107,114,128,.15);color:var(--low);border:1px solid rgba(107,114,128,.3)}}
.finding-cat{{font-family:var(--font-mono);font-size:10px;color:var(--text3)}}
.finding-cat.semantic{{color:var(--green)}}
.finding-name{{font-size:12px;font-weight:600;color:var(--text);margin-bottom:2px}}
.finding-match{{font-family:var(--font-mono);font-size:11px;color:var(--text2);overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.finding-line{{font-family:var(--font-mono);font-size:11px;color:var(--text3);text-align:right}}

.detail{{display:none;background:var(--bg);border-top:1px solid var(--border);padding:14px 16px}}
.detail.open{{display:block}}
.detail-grid{{display:grid;grid-template-columns:70px 1fr;gap:6px 12px;margin-bottom:10px}}
.dk{{font-family:var(--font-mono);font-size:10px;color:var(--text3);padding-top:2px;text-transform:uppercase}}
.dv{{font-family:var(--font-mono);font-size:11px;color:var(--text2);word-break:break-all}}
.snippet{{background:var(--bg2);border:1px solid var(--border2);border-radius:var(--radius);padding:10px 12px;font-family:var(--font-mono);font-size:11px;color:var(--text2);line-height:1.8;margin-top:4px;word-break:break-all}}
.conf-high{{color:var(--green)}}
.conf-med{{color:var(--yellow)}}
.conf-low{{color:var(--text3)}}

.chips{{display:flex;flex-wrap:wrap;gap:6px;padding:12px 16px}}
.chip-item{{font-family:var(--font-mono);font-size:11px;padding:3px 9px;border-radius:var(--radius);border:1px solid var(--border2);color:var(--text2);background:var(--bg3)}}
.chip-item.danger{{color:var(--red);border-color:rgba(239,68,68,.3);background:rgba(239,68,68,.08)}}
.chip-item.warn{{color:var(--orange);border-color:rgba(249,115,22,.3);background:rgba(249,115,22,.08)}}

.count-label{{font-family:var(--font-mono);font-size:11px;color:var(--text3)}}
.footer{{text-align:center;padding:2rem 0;font-family:var(--font-mono);font-size:11px;color:var(--text3)}}

.empty{{padding:24px 16px;text-align:center;color:var(--text3);font-size:12px}}
</style>
</head>
<body>
<div class="layout">

<div class="header">
  <div class="logo">kx</div>
  <div class="target">⌖ {_html_esc(target)}</div>
  <div class="meta">
    <span class="chip">{ts}</span>
    <span class="chip">{len(js_urls)} js files crawled</span>
    <span class="chip">{len(findings)} total findings</span>
  </div>
</div>

<div class="metrics">
  <div class="metric"><div class="metric-label">critical</div><div class="metric-val crit" id="m-critical">0</div></div>
  <div class="metric"><div class="metric-label">high</div><div class="metric-val high" id="m-high">0</div></div>
  <div class="metric"><div class="metric-label">medium</div><div class="metric-val med" id="m-medium">0</div></div>
  <div class="metric"><div class="metric-label">low</div><div class="metric-val low" id="m-low">0</div></div>
  <div class="metric"><div class="metric-label">total</div><div class="metric-val total">{len(findings)}</div></div>
  <div class="metric"><div class="metric-label">js files</div><div class="metric-val total">{len(js_urls)}</div></div>
</div>

<div class="section" id="triage-section"{triage_section_attr}>
  <div class="section-header">
    <span class="section-title">triage -- start here<span class="sub">{len(triage)} of {by_sev.get('critical',0)+by_sev.get('high',0)} high/critical</span></span>
  </div>
  <div class="triage-list" id="triage-list"></div>
</div>

<div class="section">
  <div class="section-header">
    <span class="section-title">findings</span>
    <span class="count-label" id="count-lbl">loading...</span>
  </div>
  <div class="search-row">
    <input type="search" id="search" placeholder="filter findings  (press / to focus)">
  </div>
  <div class="filters" id="filters">
    <button class="filter-btn active" onclick="setFilter('all',this)">all</button>
    <button class="filter-btn" onclick="setFilter('critical',this)">critical</button>
    <button class="filter-btn" onclick="setFilter('high',this)">high</button>
    <button class="filter-btn" onclick="setFilter('medium',this)">medium</button>
    <button class="filter-btn" onclick="setFilter('low',this)">low</button>
    <button class="filter-btn" onclick="setFilter('semantic',this)">semantic</button>
    <button class="filter-btn" onclick="setFilter('endpoint',this)">endpoints</button>
    <button class="filter-btn" onclick="setFilter('sink',this)">sinks</button>
    <button class="filter-btn" onclick="setFilter('secrets',this)">secrets</button>
    <button class="filter-btn" onclick="setFilter('sensitive',this)">sensitive fields</button>
  </div>
  <div id="findings-list"></div>
</div>

<div class="section" id="backends-section" style="display:none">
  <div class="section-header"><span class="section-title">discovered backends</span></div>
  <div class="chips" id="backends-list"></div>
</div>

<div class="section" id="admin-section" style="display:none">
  <div class="section-header"><span class="section-title">admin api surface</span></div>
  <div class="chips" id="admin-list"></div>
</div>

<div class="section" id="js-section">
  <div class="section-header">
    <span class="section-title">crawled js files</span>
    <span class="count-label">{len(js_urls)} files</span>
  </div>
  <div class="chips" id="js-list"></div>
</div>

<div class="footer">generated by kx · {ts}</div>
</div>

<script>
const FINDINGS = {findings_json};
const TRIAGE   = {triage_json};
const RT       = {rt_json};
const BACKENDS = {backends_json};
const ADMIN    = {admin_json};
const JS_URLS  = {js_json};

let currentFilter = 'all';
let searchTerm = '';

function sevClass(s){{return 'sev-'+s}}
function confClass(c){{return c==='high'||c==='verified'?'conf-high':c==='pattern+context'?'conf-med':'conf-low'}}
function trim(s,n){{return s&&s.length>n?s.slice(0,n)+'...':s||''}}
function esc(s){{return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')}}
function shortUrl(u){{
  if(!u) return '';
  if(u.startsWith('sourcemap://')) {{
    const i = u.indexOf('#'); return i>=0 ? '[src] '+u.slice(i+1) : u;
  }}
  return u.split('/').slice(-2).join('/');
}}

function evidenceHTML(ev){{
  if(!ev || !ev.length) return '';
  const rows = ev.map(e => {{
    const kind = esc(e.kind || '?');
    const ln   = e.line ? '<span class="ln">L'+e.line+'</span>' : '';
    let snip = e.snippet || '';
    if(snip.length > 320) snip = snip.slice(0,320) + '...';
    return '<div class="ev-row"><span class="ev-kind">'+kind+'</span>'
         + '<span class="ev-snip">'+ln+esc(snip)+'</span></div>';
  }}).join('');
  return '<div class="evidence">'+rows+'</div>';
}}

function matchesSearch(f){{
  if(!searchTerm) return true;
  const t = (f.name+' '+f.match+' '+(f.note||'')+' '+f.source_url).toLowerCase();
  return t.includes(searchTerm);
}}

function filtered(){{
  let arr = FINDINGS;
  if(currentFilter==='endpoint')        arr = arr.filter(f=>f.category.includes('endpoint'));
  else if(currentFilter==='sink')       arr = arr.filter(f=>f.category.includes('sink'));
  else if(currentFilter==='secrets')    arr = arr.filter(f=>f.category==='secrets');
  else if(currentFilter==='sensitive')  arr = arr.filter(f=>f.category.includes('sensitive'));
  else if(currentFilter==='semantic')   arr = arr.filter(f=>f.category.startsWith('semantic:'));
  else if(currentFilter!=='all')        arr = arr.filter(f=>f.severity===currentFilter);
  return arr.filter(matchesSearch);
}}

function renderTriage(){{
  if(!TRIAGE.length) return;
  const list = document.getElementById('triage-list');
  list.innerHTML = TRIAGE.map((f,i)=>{{
    return `<div class="triage-card ${{esc(f.severity)}}">
      <div class="triage-row">
        <span class="sev-badge ${{sevClass(f.severity)}}">${{esc(f.severity)}}</span>
        <span class="triage-name">${{esc(f.name)}}</span>
        <span class="triage-match">${{esc(f.match)}}</span>
        <span class="triage-loc">${{esc(shortUrl(f.source_url))}} · L${{esc(f.line)}}</span>
      </div>
      ${{f.note ? '<div class="triage-note">'+esc(f.note)+'</div>' : ''}}
      ${{evidenceHTML(f.evidence)}}
    </div>`;
  }}).join('');
}}

function render(){{
  const list = document.getElementById('findings-list');
  const shown = filtered();
  document.getElementById('count-lbl').textContent = shown.length+' of '+FINDINGS.length+' findings';

  const bySev = {{}};
  FINDINGS.forEach(f=>{{bySev[f.severity]=(bySev[f.severity]||0)+1}});
  ['critical','high','medium','low'].forEach(s=>{{
    const el = document.getElementById('m-'+s);
    if(el) el.textContent = bySev[s]||0;
  }});

  if(!shown.length){{
    list.innerHTML = '<div class="empty">no findings match the current filter</div>';
    return;
  }}

  list.innerHTML = shown.map((f,i)=>{{
    const fid = 'f'+i;
    const catCls = f.category.startsWith('semantic:') ? 'finding-cat semantic' : 'finding-cat';
    return `<div class="finding" onclick="toggle('${{fid}}')">
      <div class="finding-row">
        <div><span class="sev-badge ${{sevClass(f.severity)}}">${{esc(f.severity)}}</span></div>
        <div class="${{catCls}}">${{esc(f.category)}}</div>
        <div>
          <div class="finding-name">${{esc(f.name)}}</div>
          <div class="finding-match">${{esc(trim(f.match,65))}}</div>
        </div>
        <div class="finding-line">L${{esc(f.line)}}</div>
      </div>
      <div class="detail" id="${{fid}}">
        <div class="detail-grid">
          <span class="dk">file</span><span class="dv">${{esc(shortUrl(f.source_url))}}</span>
          <span class="dk">match</span><span class="dv">${{esc(f.match)}}</span>
          <span class="dk">context</span><span class="dv">${{esc(f.context||'')}}</span>
          <span class="dk">conf</span><span class="dv ${{confClass(f.confidence)}}">${{esc(f.confidence)}}</span>
        </div>
        ${{f.note ? '<div class="note">'+esc(f.note)+'</div>' : ''}}
        ${{f.snippet ? '<div class="snippet">'+esc(f.snippet)+'</div>' : ''}}
        ${{evidenceHTML(f.evidence)}}
      </div>
    </div>`;
  }}).join('');
}}

function toggle(id){{document.getElementById(id).classList.toggle('open')}}

function setFilter(f,btn){{
  currentFilter=f;
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  btn.classList.add('active');
  render();
}}

function renderChips(){{
  if(BACKENDS.length){{
    document.getElementById('backends-section').style.display='';
    document.getElementById('backends-list').innerHTML = BACKENDS.map(b=>
      `<span class="chip-item warn">${{esc(b)}}</span>`).join('');
  }}
  if(ADMIN.length){{
    document.getElementById('admin-section').style.display='';
    document.getElementById('admin-list').innerHTML = ADMIN.map(p=>{{
      const cls = p.includes('password')||p.includes('retrieve')?'danger':'';
      return `<span class="chip-item ${{cls}}">${{esc(p)}}</span>`;
    }}).join('');
  }}
  document.getElementById('js-list').innerHTML = JS_URLS.map(u=>
    `<span class="chip-item">${{esc(u.split('/').slice(-1)[0]||u)}}</span>`).join('');
}}

document.getElementById('search').addEventListener('input', e => {{
  searchTerm = e.target.value.toLowerCase().trim();
  render();
}});

window.addEventListener('keydown', e => {{
  if(e.key === '/' && document.activeElement.tagName !== 'INPUT'){{
    e.preventDefault();
    document.getElementById('search').focus();
  }}
}});

renderTriage();
render();
renderChips();
</script>
</body>
</html>"""

    Path(path).write_text(html)


def _html_esc(s) -> str:
    """Tiny server-side HTML escape for the title/target string."""
    return (str(s or "")
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;"))
