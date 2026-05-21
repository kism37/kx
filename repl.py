"""
kx -- Operator REPL

A post-scan interactive command loop. Modeled on Cobalt Strike / Sliver:
after a scan completes, the operator stays at a `kx ►` prompt with the
findings in memory and can slice them without re-running.

Commands:
    show <severity>    filter by severity (critical/high/medium/low/info)
    show <category>    filter by category substring (idor/ssrf/semantic/...)
    show <id>          show one finding's full evidence + note
    file <pattern>     show findings in files matching glob/substring
    list               re-print the current finding set
    surface            re-print the attack-surface panels
    sort sev|file|line change ordering of current view
    triage <id> fp     mark finding as false-positive (in-memory only)
    triage <id> hit    mark finding as confirmed hit
    triaged            list all triage marks
    open <id>          open the source file in $EDITOR at the finding's line
    poc <id>           ask Claude to generate a PoC (needs ANTHROPIC_API_KEY)
    export [path]      export current view to JSON
    stats              show counts by severity / category
    help, ?            this help
    quit, exit, q      leave

The REPL never persists state to disk -- exit and you lose triage marks.
For persistent triage, use the JSON export + your own workflow.
"""
from __future__ import annotations
import os
import re
import shlex
import sys
import json
import subprocess
from pathlib import Path
from typing import Callable

try:
    from rich.console import Console
    from rich.text import Text
    _RICH = True
except ImportError:
    _RICH = False


class kxRepl:
    """
    The findings list passed in is mutated only in the `_triage` dict.
    Original Finding objects are not modified.
    """

    def __init__(self, target: str, findings: list, js_results: list, console=None):
        self.target = target
        self.findings = sorted(
            findings,
            key=lambda f: (
                -{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
                  .get(f.severity, 0),
                0 if f.category.startswith("semantic:") else 1,
                f.source_url or "",
                f.line or 0,
            ),
        )
        self.js_results = js_results
        # current "view" -- what `list` and `show` last produced
        self.current_view: list = list(self.findings)
        # in-memory triage marks: id -> "fp" | "hit"
        self._triage: dict[int, str] = {}
        # Set when triage changes; cleared on save. Prevents redundant
        # autosave on quit when nothing changed since the last save.
        self._dirty = False
        self.console = console
        self._url_to_content = {r.url: r.content for r in js_results}

    # ── utility ────────────────────────────────────────────────────────

    def _ts(self):
        import datetime as dt
        return dt.datetime.now().strftime("%H:%M:%S")

    def _print(self, msg=""):
        if self.console:
            self.console.print(msg)
        else:
            print(msg)

    def _err(self, msg):
        if self.console:
            self.console.print(f"  [red][×][/] [red]ERR[/]   {msg}")
        else:
            print(f"  [×] ERR   {msg}")

    def _ok(self, msg):
        if self.console:
            self.console.print(f"  [green][+][/] [dim]OK[/]    {msg}")
        else:
            print(f"  [+] OK    {msg}")

    def _info(self, msg):
        if self.console:
            self.console.print(f"  [bright_white][*][/] [dim]INFO[/]  {msg}")
        else:
            print(f"  [*] INFO  {msg}")

    def _short_url(self, url: str, n: int = 50) -> str:
        if url.startswith("sourcemap://"):
            path = url.split("#", 1)[1] if "#" in url else url
            prefix = "[src] "
            if len(prefix) + len(path) <= n:
                return prefix + path
            return prefix + "..." + path[-(n - len(prefix) - 1):]
        if len(url) <= n: return url
        return "..." + url[-(n - 1):]

    # ── rendering ──────────────────────────────────────────────────────

    def _render_list(self, items: list, *, with_id: bool = True):
        """Compact, ID-prefixed list. The IDs are positions in self.findings."""
        if not items:
            self._info("[dim](empty view)[/]")
            return
        sev_color = {
            "critical": "bright_red", "high": "red", "medium": "bright_yellow",
            "low": "cyan", "info": "dim",
        }
        for f in items:
            try:
                fid = self.findings.index(f)
            except ValueError:
                fid = -1
            sev = f.severity
            color = sev_color.get(sev, "white")
            sev_pill = f"[black on {color}] {sev.upper():<8}[/]"
            tri = self._triage.get(fid)
            tri_tag = ""
            if tri == "fp":  tri_tag = " [black on bright_white] FP [/]"
            elif tri == "hit": tri_tag = " [black on bright_green] HIT [/]"
            sem_tag = "" if not f.category.startswith("semantic:") else " [black on bright_magenta]SEM[/]"
            id_tag = f"[bright_yellow]#{fid:<3}[/]" if with_id else "    "
            match = (f.match or "")[:55]
            line = (
                f"  {id_tag}  {sev_pill}  "
                f"[dim]{f.category[:18]:<18}[/] "
                f"[bold]{f.name[:50]}[/]"
                f"{sem_tag}{tri_tag}"
            )
            self._print(line)
            self._print(
                f"          [dim]►[/] [bright_yellow]{match}[/]  "
                f"[dim]·[/] [cyan]{self._short_url(f.source_url, 40)}[/][dim]:[/][bright_cyan]L{f.line or '?'}[/]"
            )

    def _render_one(self, f, fid: int):
        """Full detail view of a single finding."""
        sev_color = {
            "critical": "bright_red", "high": "red", "medium": "bright_yellow",
            "low": "cyan", "info": "dim",
        }.get(f.severity, "white")
        self._print()
        self._print(
            f"  [bright_yellow]#{fid}[/]  "
            f"[black on {sev_color}] {f.severity.upper():<8}[/]  "
            f"[bold]{f.name}[/]"
        )
        self._print(f"  [dim]category:[/]  {f.category}")
        self._print(f"  [dim]target:  [/]  [bright_yellow]{f.match}[/]")
        self._print(f"  [dim]file:    [/]  [cyan]{self._short_url(f.source_url, 70)}[/][dim]:[/][bright_cyan]L{f.line or '?'}[/]")
        self._print(f"  [dim]conf:    [/]  {f.confidence}")
        if f.note:
            self._print()
            from textwrap import wrap
            for ln in wrap(f.note, width=74):
                self._print(f"  [white]{ln}[/]")
        if f.evidence:
            self._print()
            self._print("  [dim]evidence chain:[/]")
            for ev in f.evidence:
                kind = ev.get("kind", "?")[:22]
                snip = (ev.get("snippet") or "").replace("\n", " ")[:110]
                self._print(f"    [dim]│[/] [bright_black]{kind:<22}[/] [dim]{snip}[/]")
        tri = self._triage.get(fid)
        if tri:
            self._print()
            self._print(f"  [dim]triage:[/]  [bright_white]{tri.upper()}[/]")
        self._print()

    # ── command handlers ───────────────────────────────────────────────

    def cmd_help(self, _args):
        helps = [
            ("show <sev>",         "filter by severity (critical/high/medium/low)"),
            ("show <cat>",         "filter by category substring (idor, ssrf, sem, ...)"),
            ("show <id>",          "show full detail of one finding"),
            ("file <pattern>",     "show findings whose source URL contains pattern"),
            ("list",               "re-print the current view"),
            ("surface",            "re-print attack-surface panels"),
            ("sort sev|file|line", "re-sort current view"),
            ("",                   ""),
            ("triage <id> fp/hit", "mark finding as false-positive / confirmed hit"),
            ("triaged",            "list all triage marks"),
            ("save / load",        "persist triage marks to reports/<host>/.kx_session"),
            ("",                   ""),
            ("open <id>",          "open file in $EDITOR at finding's line"),
            ("curl <id>",          "generate curl command to test the endpoint (-X / -H / --auth / --proxy)"),
            ("poc <id>",           "generate PoC via Claude (needs ANTHROPIC_API_KEY)"),
            ("",                   ""),
            ("history",            "show prior scans of this target from the diff DB"),
            ("stats",              "counts by severity / category"),
            ("export [path]",      "export current view to JSON"),
            ("clear",              "clear screen"),
            ("quit / exit / q",    "leave repl"),
        ]
        self._print()
        self._print("  [bold]commands[/]")
        for cmd, desc in helps:
            if not cmd:
                self._print()
                continue
            self._print(f"    [bright_green]{cmd:<22}[/] [dim]{desc}[/]")
        self._print()

    def cmd_list(self, _args):
        self._info(f"current view: [bright_white]{len(self.current_view)}[/] of {len(self.findings)} findings")
        self._render_list(self.current_view)

    def cmd_show(self, args):
        if not args:
            return self.cmd_list(args)
        token = args[0].lower()
        # numeric → single finding detail
        if token.isdigit():
            fid = int(token)
            if 0 <= fid < len(self.findings):
                self._render_one(self.findings[fid], fid)
            else:
                self._err(f"no finding with id #{fid}")
            return
        # severity
        if token in ("critical", "high", "medium", "low", "info"):
            view = [f for f in self.findings if f.severity == token]
            self.current_view = view
            self._info(f"filter [bright_white]severity={token}[/]: [bright_white]{len(view)}[/] result(s)")
            self._render_list(view)
            return
        # category substring (semantic, idor, ssrf, sink, endpoint, ...)
        view = [f for f in self.findings if token in (f.category or "").lower()
                or token in (f.name or "").lower()]
        self.current_view = view
        self._info(f"filter [bright_white]{token}[/]: [bright_white]{len(view)}[/] result(s)")
        self._render_list(view)

    def cmd_file(self, args):
        if not args:
            self._err("usage: file <pattern>")
            return
        pat = args[0].lower()
        view = [f for f in self.findings if pat in (f.source_url or "").lower()]
        self.current_view = view
        self._info(f"file filter [bright_white]{pat}[/]: [bright_white]{len(view)}[/] result(s)")
        self._render_list(view)

    def cmd_surface(self, _args):
        # Import lazily so we don't depend on reporter at REPL construction time
        from reporter import print_attack_surface
        print_attack_surface(self.findings)

    def cmd_sort(self, args):
        key = (args[0] if args else "sev").lower()
        if key in ("sev", "severity"):
            rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
            self.current_view.sort(key=lambda f: (-rank.get(f.severity, 0), f.line or 0))
        elif key == "file":
            self.current_view.sort(key=lambda f: (f.source_url or "", f.line or 0))
        elif key == "line":
            self.current_view.sort(key=lambda f: (f.line or 0))
        else:
            self._err(f"sort key '{key}' not understood (sev|file|line)")
            return
        self._ok(f"sorted by [bright_white]{key}[/]")
        self._render_list(self.current_view)

    def cmd_triage(self, args):
        if len(args) < 2 or not args[0].isdigit():
            self._err("usage: triage <id> fp|hit|verify|clear")
            return
        fid = int(args[0])
        verdict = args[1].lower()
        if fid not in range(len(self.findings)):
            self._err(f"no finding with id #{fid}")
            return
        if verdict in ("fp", "false-positive", "false_positive"):
            self._triage[fid] = "fp"
            self.findings[fid].verdict = "fp"
            self.findings[fid].verdict_reason = "operator marked FP in REPL"
            self._dirty = True
            self._ok(f"#{fid} marked FALSE POSITIVE")
        elif verdict in ("hit", "confirmed", "true", "tp", "real"):
            self._triage[fid] = "hit"
            self.findings[fid].verdict = "real"
            self.findings[fid].verdict_reason = "operator confirmed in REPL"
            self._dirty = True
            self._ok(f"#{fid} marked CONFIRMED HIT")
        elif verdict in ("verify", "check", "?"):
            self._triage[fid] = "verify"
            self.findings[fid].verdict = "verify"
            self.findings[fid].verdict_reason = "operator flagged for verification"
            self._dirty = True
            self._ok(f"#{fid} marked NEEDS VERIFICATION")
        elif verdict in ("clear", "reset", "unmark"):
            self._triage.pop(fid, None)
            self.findings[fid].verdict = ""
            self.findings[fid].verdict_reason = ""
            self._dirty = True
            self._ok(f"#{fid} triage cleared")
        else:
            self._err(f"verdict '{verdict}' not understood (fp/hit/verify/clear)")

    def cmd_triaged(self, _args):
        if not self._triage:
            self._info("no triage marks set")
            return
        self._info(f"[bright_white]{len(self._triage)}[/] triage mark(s):")
        for fid, verdict in self._triage.items():
            f = self.findings[fid]
            color = {"fp": "bright_white", "hit": "bright_green"}.get(verdict, "white")
            self._print(
                f"    [bright_yellow]#{fid:<3}[/]  "
                f"[black on {color}] {verdict.upper():<4}[/]  "
                f"[bold]{f.name[:50]}[/]  [dim]({f.match[:30]})[/]"
            )

    def cmd_open(self, args):
        if not args or not args[0].isdigit():
            self._err("usage: open <id>")
            return
        fid = int(args[0])
        if fid not in range(len(self.findings)):
            self._err(f"no finding with id #{fid}")
            return
        f = self.findings[fid]
        content = self._url_to_content.get(f.source_url, "")
        if not content:
            self._err("source content not available in this session")
            return
        # Write the content to a temp file and open in $EDITOR
        import tempfile
        suffix = ".js"
        if f.source_url.startswith("sourcemap://"):
            path = f.source_url.split("#", 1)[1] if "#" in f.source_url else ""
            for ext in (".ts", ".tsx", ".jsx", ".vue", ".svelte"):
                if path.endswith(ext):
                    suffix = ext
                    break
        tmp = tempfile.NamedTemporaryFile(suffix=suffix, delete=False, mode="w")
        tmp.write(content)
        tmp.close()
        editor = os.getenv("EDITOR", "less")
        line = max(1, f.line or 1)
        # Most editors accept +N filename; vi/vim/nvim/emacs/nano all do.
        try:
            if editor in ("vi", "vim", "nvim", "nano", "emacs"):
                subprocess.run([editor, f"+{line}", tmp.name])
            elif editor == "code":
                subprocess.run([editor, "-g", f"{tmp.name}:{line}"])
            elif editor == "less":
                # less needs a different invocation for line nav
                subprocess.run([editor, f"+{line}g", tmp.name])
            else:
                subprocess.run([editor, tmp.name])
        except FileNotFoundError:
            self._err(f"editor '{editor}' not found -- set $EDITOR")
        finally:
            os.unlink(tmp.name)

    def cmd_poc(self, args):
        if not args or not args[0].isdigit():
            self._err("usage: poc <id>")
            return
        fid = int(args[0])
        if fid not in range(len(self.findings)):
            self._err(f"no finding with id #{fid}")
            return
        if not os.getenv("ANTHROPIC_API_KEY"):
            self._err("ANTHROPIC_API_KEY not set")
            return
        f = self.findings[fid]
        # Use verifier module to ask Claude
        try:
            import asyncio
            from verifier import verify_finding
        except ImportError:
            self._err("verifier module unavailable")
            return
        self._info(f"asking claude to verify and write PoC for [bright_white]#{fid}[/]...")
        source = self._url_to_content.get(f.source_url, "")
        try:
            res = asyncio.run(verify_finding(
                f, source, api_key=os.getenv("ANTHROPIC_API_KEY")
            ))
        except Exception as e:
            self._err(f"verifier failed: {e}")
            return
        if not res:
            self._err("verifier returned no result")
            return
        self._print()
        self._print(f"  [bold]verdict:[/]  [bright_white]{res.verdict}[/]  [dim](cvss≈{res.cvss_estimate})[/]")
        self._print(f"  [bold]reasoning:[/]")
        from textwrap import wrap
        for ln in wrap(res.analyst_note, width=72):
            self._print(f"    [white]{ln}[/]")
        if res.poc:
            self._print()
            self._print(f"  [bold]PoC:[/]")
            for ln in res.poc.split("\n"):
                self._print(f"    [bright_yellow]{ln}[/]")
        if res.prerequisites:
            self._print()
            self._print(f"  [bold]prerequisites:[/] [dim]{res.prerequisites}[/]")
        if res.chain_notes:
            self._print()
            self._print(f"  [bold]chaining:[/] [dim]{res.chain_notes}[/]")
        self._print()

    def cmd_export(self, args):
        path = Path(args[0]) if args else Path(f"kx_view_{int(__import__('time').time())}.json")
        data = []
        for f in self.current_view:
            try:
                fid = self.findings.index(f)
            except ValueError:
                fid = -1
            d = f.to_dict() if hasattr(f, "to_dict") else dict(
                category=f.category, name=f.name, severity=f.severity,
                match=f.match, line=f.line, source_url=f.source_url,
                confidence=f.confidence, note=getattr(f, "note", ""),
                evidence=getattr(f, "evidence", []),
            )
            d["id"] = fid
            d["triage"] = self._triage.get(fid)
            data.append(d)
        path.write_text(json.dumps(data, indent=2))
        self._ok(f"exported {len(data)} finding(s) → [cyan]{path}[/]")

    def cmd_stats(self, _args):
        from collections import Counter
        by_sev = Counter(f.severity for f in self.findings)
        by_cat = Counter(f.category for f in self.findings)
        self._print()
        self._print("  [bold]by severity[/]")
        for s in ("critical", "high", "medium", "low", "info"):
            n = by_sev.get(s, 0)
            if not n: continue
            self._print(f"    {s.upper():<10}  [bright_white]{n:>4}[/]")
        self._print()
        self._print("  [bold]top categories[/]")
        for cat, n in by_cat.most_common(10):
            self._print(f"    [dim]{cat:<28}[/]  [bright_white]{n:>4}[/]")
        self._print()

    def cmd_curl(self, args):
        """
        Generate a curl command to test a finding's endpoint.

        For endpoint-class findings (admin paths, API routes, auth surfaces),
        the most common next step is "curl it and see what happens." Doing
        this by hand means: pull the host from the source URL, the path from
        the match, decide HTTP method, decide whether to attach auth cookies
        the user has in the env. Tedious. This automates it.

        Examples:
          curl 14                      # GET, no auth, infer host from source_url
          curl 14 -X POST              # method override
          curl 14 -H "Cookie: x=y"     # extra headers (repeatable)
          curl 14 --auth               # pull cookie from $KX_COOKIE
          curl 14 --proxy 127.0.0.1:8080   # route through burp/zap
        """
        if not args or not args[0].isdigit():
            self._err("usage: curl <id> [-X METHOD] [-H 'Header: value'] [--auth] [--proxy host:port]")
            return
        fid = int(args[0])
        if fid not in range(len(self.findings)):
            self._err(f"no finding with id #{fid}")
            return
        f = self.findings[fid]

        # Parse optional args
        rest = args[1:]
        method = "GET"
        headers: list[str] = []
        use_auth = False
        proxy = None
        i = 0
        while i < len(rest):
            tok = rest[i]
            if tok in ("-X", "--method") and i + 1 < len(rest):
                method = rest[i + 1].upper()
                i += 2
            elif tok in ("-H", "--header") and i + 1 < len(rest):
                headers.append(rest[i + 1])
                i += 2
            elif tok == "--auth":
                use_auth = True
                i += 1
            elif tok == "--proxy" and i + 1 < len(rest):
                proxy = rest[i + 1]
                i += 2
            else:
                self._err(f"unknown curl arg: {tok}")
                return

        # Resolve the URL. Strategy:
        #   1. If match is a full URL → use it
        #   2. If match is a path → join with source URL's host
        #   3. If match is a field/param name (semantic findings) → use the
        #      source URL itself, and surface the param as a hint
        from urllib.parse import urlparse, urljoin
        match = (f.match or "").strip().strip('"').strip("'").strip("`")
        param_hint = None
        if match.startswith(("http://", "https://")):
            target_url = match
        elif match.startswith("/"):
            src = urlparse(f.source_url or "")
            if not src.netloc:
                self._err(f"can't infer host (source_url={f.source_url!r})")
                return
            target_url = f"{src.scheme}://{src.netloc}{match}"
        else:
            # Match is a field/param name -- use the source URL itself.
            # This is the common path for IDOR / semantic findings where
            # match is "merchantID" or "whoCanChange".
            if not (f.source_url or "").startswith(("http://", "https://")):
                self._err(f"match isn't URL-shaped and source_url is unusable: {f.source_url!r}")
                return
            target_url = f.source_url
            param_hint = match

        # Build the curl command
        parts = ["curl", "-sS", "-i"]
        if method != "GET":
            parts += ["-X", method]
        if use_auth:
            cookie = os.getenv("KX_COOKIE")
            if not cookie:
                self._err("--auth set but $KX_COOKIE is empty")
                return
            parts += ["-H", f'"Cookie: {cookie}"']
        for h in headers:
            parts += ["-H", f'"{h}"']
        if proxy:
            parts += ["-x", proxy]
        parts.append(f'"{target_url}"')
        cmd = " ".join(parts)

        # Render with hint about what to look for
        self._print()
        self._print(f"  [dim]target:[/]  [bright_yellow]{target_url}[/]")
        self._print(f"  [dim]finding:[/] [bold]{f.name}[/]  [dim]({f.severity})[/]")
        self._print()
        self._print(f"  [bright_green]{cmd}[/]")
        self._print()
        # Hints tied to finding category
        hints = []
        cat = (f.category or "").lower()
        if param_hint:
            hints.append(f"manipulate field [bright_yellow]{param_hint}[/] in the request body / query string")
        if "admin" in (f.name or "").lower() or "/admin" in match.lower():
            hints.append("expect 302 → /login if authz works; 200 with content = missing server-side check")
        if "idor" in cat:
            hints.append("change the ID to one belonging to another tenant/user")
        if "ssrf" in cat:
            hints.append("set the URL param to http://169.254.169.254/ (cloud metadata) or http://localhost/")
        if "redirect" in (f.name or "").lower():
            hints.append("set the redirect param to https://attacker.com and follow the chain (-L)")
        if "priv" in cat or "permission" in (f.name or "").lower():
            hints.append("set the permission field to an elevated value (true, admin, *)")
        if hints:
            self._print(f"  [dim]hints:[/]")
            for h in hints:
                self._print(f"    [dim]·[/] [white]{h}[/]")
            self._print()

    def cmd_history(self, _args):
        """Show previous scans of this target from the diff DB."""
        try:
            from differ import DiffEngine, DEFAULT_DB
        except ImportError:
            self._err("differ module unavailable")
            return
        try:
            engine = DiffEngine(db_path=DEFAULT_DB)
            scans = engine.history(self.target, limit=20)
            engine.close()
        except Exception as e:
            self._err(f"history query failed: {e}")
            return
        if not scans:
            self._info("no prior scans of this target recorded ([dim]kx needs --diff to write history[/])")
            return
        import datetime as _dt
        self._info(f"[bright_white]{len(scans)}[/] prior scan(s) of [cyan]{self.target}[/]:")
        for s in scans:
            ts = _dt.datetime.fromtimestamp(s["started_at"]).strftime("%Y-%m-%d %H:%M")
            elapsed = (s["finished_at"] or 0) - s["started_at"]
            elapsed_s = f"{elapsed}s" if elapsed else "--"
            self._print(
                f"    [bright_yellow]#{s['id']:<3}[/]  "
                f"[dim]{ts}[/]  "
                f"[bright_white]{s['finding_count']:>4}[/] findings  "
                f"[dim]·[/]  [bright_white]{s['js_count']:>4}[/] js  "
                f"[dim]·[/]  [dim]{elapsed_s}[/]"
            )

    def cmd_save(self, args):
        """Persist triage marks + view to reports/<host>/.kx_session.json."""
        from urllib.parse import urlparse
        host = urlparse(self.target).netloc.replace(":", "_") or "unknown"
        session_dir = Path("reports") / host
        session_dir.mkdir(parents=True, exist_ok=True)
        path = Path(args[0]) if args else session_dir / ".kx_session.json"
        data = {
            "target":   self.target,
            "saved_at": int(__import__("time").time()),
            "triage":   {
                str(fid): {
                    "verdict":     v,
                    "name":        self.findings[fid].name,
                    "match":       self.findings[fid].match,
                    "source_url":  self.findings[fid].source_url,
                    "line":        self.findings[fid].line,
                    "fingerprint": self._fingerprint(self.findings[fid]),
                }
                for fid, v in self._triage.items()
            },
        }
        try:
            path.write_text(json.dumps(data, indent=2))
            self._ok(f"session saved → [cyan]{path}[/]")
            self._dirty = False
        except Exception as e:
            self._err(f"save failed: {e}")

    def cmd_load(self, args):
        """Restore triage marks from a previous session file."""
        from urllib.parse import urlparse
        host = urlparse(self.target).netloc.replace(":", "_") or "unknown"
        default = Path("reports") / host / ".kx_session.json"
        path = Path(args[0]) if args else default
        if not path.exists():
            self._err(f"no session file at [cyan]{path}[/]")
            return
        try:
            data = json.loads(path.read_text())
        except Exception as e:
            self._err(f"load failed: {e}")
            return

        # Match by fingerprint, not by id (id ordering may have changed)
        prev_triage = data.get("triage", {})
        fp_to_verdict = {entry.get("fingerprint"): entry.get("verdict")
                         for entry in prev_triage.values()
                         if entry.get("fingerprint")}
        restored = 0
        for fid, finding in enumerate(self.findings):
            fp = self._fingerprint(finding)
            if fp in fp_to_verdict:
                self._triage[fid] = fp_to_verdict[fp]
                restored += 1
        if restored:
            self._dirty = False  # just synced from disk; nothing to write back
        unmatched = len(fp_to_verdict) - restored
        if restored:
            self._ok(f"restored [bright_white]{restored}[/] triage mark(s) from [cyan]{path}[/]")
        else:
            self._info(f"no matching findings in this scan ([dim]{len(fp_to_verdict)} marks in file[/])")
        if unmatched:
            self._info(f"[dim]{unmatched} previous mark(s) didn't match -- likely fixed or moved.[/]")

    def _fingerprint(self, f) -> str:
        """Stable fingerprint of a finding for cross-scan matching."""
        import hashlib
        key = f"{f.category}|{f.name}|{f.match}|{f.source_url}"
        return hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]

    def _autosave_on_exit(self):
        """Persist triage marks to reports/<host>/.kx_session.json on quit."""
        if not self._triage or not getattr(self, "_dirty", False):
            return
        try:
            self.cmd_save([])
        except Exception:
            pass

    def cmd_clear(self, _args):
        if self.console:
            self.console.clear()
        else:
            os.system("clear" if os.name == "posix" else "cls")

    # ── main loop ──────────────────────────────────────────────────────

    def run(self):
        commands: dict[str, Callable] = {
            "help": self.cmd_help, "?": self.cmd_help,
            "list": self.cmd_list, "ls": self.cmd_list,
            "show": self.cmd_show,
            "file": self.cmd_file,
            "surface": self.cmd_surface, "attack-surface": self.cmd_surface,
            "sort": self.cmd_sort,
            "triage": self.cmd_triage,
            "triaged": self.cmd_triaged,
            "open": self.cmd_open, "edit": self.cmd_open,
            "poc": self.cmd_poc,
            "curl": self.cmd_curl,
            "history": self.cmd_history, "hist": self.cmd_history,
            "save": self.cmd_save,
            "load": self.cmd_load, "restore": self.cmd_load,
            "export": self.cmd_export,
            "stats": self.cmd_stats,
            "clear": self.cmd_clear, "cls": self.cmd_clear,
        }

        self._print()
        if self.console:
            self.console.print(
                f"  [bold bright_green]kx[/][bright_green] ►[/] "
                f"[dim]operator console · {len(self.findings)} finding(s) loaded · "
                f"type[/] [bright_green]help[/][dim] for commands · [/]"
                f"[bright_green]q[/][dim] to leave[/]"
            )

        # Auto-detect previous session for this host. If there's a session
        # file with triage marks that match findings in this scan, mention
        # it so the operator knows to `load`.
        try:
            from urllib.parse import urlparse
            host = urlparse(self.target).netloc.replace(":", "_") or "unknown"
            prev = Path("reports") / host / ".kx_session.json"
            if prev.exists():
                data = json.loads(prev.read_text())
                n = len(data.get("triage", {}))
                if n:
                    self._info(
                        f"prior session for [cyan]{host}[/] has [bright_white]{n}[/] "
                        f"triage mark(s) -- type [bright_green]load[/] to restore"
                    )
        except Exception:
            pass

        self._print()

        while True:
            try:
                if self.console:
                    raw = self.console.input("  [bold bright_green]kx[/][bright_green] ►[/] ")
                else:
                    raw = input("  kx ► ")
            except (EOFError, KeyboardInterrupt):
                self._print()
                self._info("leaving repl")
                self._autosave_on_exit()
                return
            raw = raw.strip()
            if not raw:
                continue
            try:
                parts = shlex.split(raw)
            except ValueError as e:
                self._err(f"parse error: {e}")
                continue
            cmd, args = parts[0].lower(), parts[1:]
            if cmd in ("quit", "exit", "q"):
                self._info("leaving repl")
                self._autosave_on_exit()
                return
            handler = commands.get(cmd)
            if not handler:
                self._err(f"unknown command: [bright_white]{cmd}[/] (try [bright_green]help[/])")
                continue
            try:
                handler(args)
            except Exception as e:
                self._err(f"command failed: {type(e).__name__}: {e}")


def start_repl(target: str, findings: list, js_results: list, console=None):
    """Convenience entry -- instantiate and run."""
    # Only start the REPL if we're attached to a terminal
    if not sys.stdin.isatty():
        return
    repl = kxRepl(target=target, findings=findings,
                      js_results=js_results, console=console)
    repl.run()
