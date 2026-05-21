#!/usr/bin/env python3
"""
██╗    ██╗██████╗  █████╗ ██╗████████╗██╗  ██╗
██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║  ██║
██║ █╗ ██║██████╔╝███████║██║   ██║   ███████║
██║███╗██║██╔══██╗██╔══██║██║   ██║   ██╔══██║
╚███╔███╔╝██║  ██║██║  ██║██║   ██║   ██║  ██║
 ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝
  JS Intelligence Extractor -- by kx
"""

import asyncio
import argparse
import sys
import time
import json
from pathlib import Path
from urllib.parse import urlparse

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from crawler import Crawler
from extractor import extract, Finding
from classifier import run_ast, classify
from runtime import run_runtime, PLAYWRIGHT_AVAILABLE
from differ import DiffEngine
from reporter import (
    print_banner, print_progress, print_findings,
    print_runtime_findings, print_diff_summary,
    print_summary, export_json, export_markdown, export_html,
)
from integrations.burp import push_to_burp
from integrations.journal import append_to_journal


def parse_auth_header(raw: str | None) -> dict:
    """Parse 'Header: value' or 'Cookie: x=y' into a dict."""
    if not raw:
        return {}
    headers = {}
    for part in raw.split(";;"):
        part = part.strip()
        if ":" in part:
            k, v = part.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers


def build_output_filename(target: str, ext: str, base: Path | None = None) -> Path:
    """
    Output paths: ./reports/<host>/kx_<timestamp>.<ext>

    Each target gets its own directory under reports/ so multi-target
    hunts don't mingle artifacts. The host segment keeps dots so it
    matches what the operator sees in their browser (portal.unilorin.edu.ng
    not portal_unilorin_edu_ng).
    """
    host = urlparse(target).netloc.replace(":", "_") or "unknown_target"
    ts = int(time.time())
    base = base or Path("reports")
    out_dir = base / host
    out_dir.mkdir(parents=True, exist_ok=True)
    return out_dir / f"kx_{ts}.{ext}"


async def main(args: argparse.Namespace):
    start = time.time()

    auth_headers = parse_auth_header(args.auth)

    mode_flags = {
        "runtime": args.runtime,
        "diff":    args.diff,
        "burp":    bool(args.burp),
        "ast":     not args.no_ast,
        "verify":  bool(args.verify),
    }

    print_banner(args.url, mode_flags, config={
        "depth": args.depth,
        "concurrency": args.concurrency,
        "delay": args.delay,
        "crawl_limit": args.crawl_limit or "∞",
        "ast_limit": args.ast_limit if not args.no_ast else None,
        "scope": args.scope or "",
    })

    # ── 1. Crawl ────────────────────────────────────────────────────────
    print_progress(f"crawling {args.url}", phase="crawl")

    if args.insecure:
        # We import lazily to keep the early flow simple; just want a visible
        # warning so the operator knows certs aren't being checked.
        from reporter import print_warn as _pw
        _pw("SSL certificate verification disabled ([bright_yellow]--insecure[/])", phase="warn")

    crawler = Crawler(
        target=args.url,
        auth_headers=auth_headers,
        max_depth=args.depth,
        concurrency=args.concurrency,
        delay=args.delay,
        scope_domains=args.scope.split(",") if args.scope else None,
        recover_source_maps=not args.no_source_maps,
        include_sourcemap_noise=args.sourcemap_noise,
        max_resources=(args.crawl_limit or None),
        verify_ssl=not args.insecure,
    )

    crawl_results = await crawler.crawl()
    js_results = [r for r in crawl_results if crawler._is_js(r.url, r.content_type)
                  or r.url.startswith("sourcemap://")]

    from reporter import print_ok, print_warn, print_fail, print_neg
    cap_note = ""
    if getattr(crawler, "cap_reached", False):
        cap_note = f" [yellow]· cap hit at --crawl-limit {args.crawl_limit}[/]"
    print_ok(
        f"crawl complete -- [bright_white]{len(crawl_results)}[/] resource(s), "
        f"[bright_white]{len(js_results)}[/] js file(s)"
        + (f" [dim](incl. {crawler.sourcemap_recovered} from sourcemaps)[/]"
           if crawler.sourcemap_recovered else "")
        + cap_note,
        phase="crawl",
    )

    # ── Diagnostic: if we got nothing, explain why ──────────────────────
    if not crawl_results:
        # Find the error against the root URL specifically
        root_err = next(
            (e for e in crawler.fetch_errors if e.get("url", "").rstrip("/") == args.url.rstrip("/")),
            None,
        ) or (crawler.fetch_errors[0] if crawler.fetch_errors else None)
        print_fail("no resources fetched -- scan cannot proceed", phase="error")
        if root_err:
            print_neg(f"root URL: [cyan]{root_err['url']}[/]")
            print_neg(f"reason:   [yellow]{root_err.get('reason', 'unknown')}[/]")
            if root_err.get("status"):
                print_neg(f"status:   HTTP [bright_red]{root_err['status']}[/]")
            if root_err.get("body_preview"):
                print_progress(f"   Body:     {root_err['body_preview'][:120]}")
            # Common-cause hints
            reason = (root_err.get("reason") or "").lower()
            status = root_err.get("status")
            preview = (root_err.get("body_preview") or "").lower()
            if status == 403 and ("allowlist" in preview or "whitelist" in preview or "forbidden" in preview):
                print_progress("   Hint:     server uses an IP/host allowlist. Run from a permitted")
                print_progress("             network, or scan a different deploy of the same app.")
            elif status in (401, 403):
                print_progress("   Hint:     try --auth 'Cookie: ...' to send session credentials.")
            elif "certificate_verify_failed" in reason or "ssl" in reason or "certificate verify failed" in reason:
                print_progress("   Hint:     target has a broken SSL chain (server didn't bundle the")
                print_progress("             intermediate CA). Browsers repair this via AIA; kx doesn't.")
                print_progress("             Re-run with [bright_yellow]--insecure[/] to skip cert verification.")
            elif "connect error" in reason or "name or service not known" in reason:
                print_progress("   Hint:     DNS or network failure. Check the URL spelling and that")
                print_progress("             your machine can resolve/reach the host.")
            elif "timeout" in reason:
                print_progress("   Hint:     server is slow or blocking you. Try --delay 1 or a VPN.")
        else:
            print_progress("   No errors recorded -- check the URL and try --depth 1 --concurrency 1.")
        return  # Don't bother running detectors on an empty result set
    elif crawler.fetch_errors and len(crawl_results) < 3:
        # Got SOMETHING but suspiciously little -- surface the errors as info
        n = len(crawler.fetch_errors)
        print_progress(f"ⓘ  {n} fetch error(s) during crawl -- some URLs were blocked or unreachable.")
        for e in crawler.fetch_errors[:3]:
            print_progress(f"   · {e.get('url')} → {e.get('reason')}")
            if "WAF" in (e.get("reason") or "") or "challenge" in (e.get("reason") or "").lower():
                print_progress("   Hint:     server returned a WAF/bot challenge page. Try --runtime")
                print_progress("             so Playwright can execute the challenge in a real browser.")

    # ── Diagnostic: page fetched but no JS found ────────────────────────
    if crawl_results and len(js_results) == 0:
        # The root loaded but we found no JS -- common SPA pattern where
        # scripts are injected at runtime, or the page is fully server-rendered.
        print_progress("ⓘ  Page loaded but no JS files were referenced statically.")
        if not args.runtime:
            print_progress("   Hint:     this is common for SPAs that inject script tags at runtime,")
            print_progress("             or for fully server-rendered pages. Try --runtime to use")
            print_progress("             Playwright and capture every JS file the page actually loads.")
        else:
            print_progress("   Even with --runtime, no JS was loaded. The page may be plain HTML")
            print_progress("   with no client-side code, or your auth headers may be missing.")

    # ── 2. Static extraction ────────────────────────────────────────────
    from reporter import (
        print_ok, print_warn, print_neg, print_attack_surface,
        print_operator_prompt, print_section, LiveTracker,
    )
    all_findings: list[Finding] = []

    html_results = [r for r in crawl_results if "html" in r.content_type]
    static_total = len(js_results) + len(html_results)
    print_progress(f"static pattern extraction on {static_total} file(s)", phase="static")

    # Live counter -- silent phases on big targets used to look hung. The
    # tracker shows files-done, last-filename, % bar in place. Once the
    # phase is done, the live line is wiped and replaced with the [+] ok.
    with LiveTracker(phase="static", total=static_total, label="extracting") as live:
        for result in js_results:
            findings = extract(result.url, result.content)
            all_findings.extend(findings)
            fname = result.url.rsplit("/", 1)[-1] or result.url
            live.tick(last=fname)
        # Inline scripts in HTML get the same patterns run.
        for result in html_results:
            findings = extract(result.url, result.content)
            all_findings.extend(findings)
            fname = result.url.rsplit("/", 1)[-1] or result.url
            live.tick(last=fname)
        live.done(f"static extraction: {len(all_findings)} raw finding(s) from {static_total} file(s)")

    # ── 3. AST analysis ─────────────────────────────────────────────────
    if not args.no_ast:
        # AST is expensive (subprocess per file). Pick a smart subset:
        #   Tier 1: files static extraction already hit (most likely to yield)
        #   Tier 2: largest remaining files (most likely to contain logic)
        static_hit = {f.source_url for f in all_findings}
        tier1 = [r for r in js_results if r.url in static_hit]
        tier2 = sorted(
            [r for r in js_results if r.url not in static_hit],
            key=lambda r: len(r.content), reverse=True,
        )
        ast_targets = (tier1 + tier2)[:args.ast_limit]
        skipped = max(0, len(js_results) - len(ast_targets))

        # Header line: announce the run with tier counts + skip notice.
        print_progress(
            f"running AST on {len(ast_targets)} file(s) "
            f"[dim][tier1={len(tier1)} tier2≤{max(0, args.ast_limit-len(tier1))}][/]"
            + (f"  [yellow]· {skipped} skipped (--ast-limit)[/]" if skipped else ""),
            phase="ast",
        )

        # Live-update line: gets wiped on exit; replaced by the final [+] OK.
        with LiveTracker(phase="ast", total=len(ast_targets), label="parsing") as live:
            async def _ast_one(res):
                fs = await run_ast(res.url, res.content)
                fname = res.url.rsplit("/", 1)[-1] or res.url
                live.tick(last=fname)
                return fs
            ast_results = await asyncio.gather(*[_ast_one(r) for r in ast_targets])
            ast_total = sum(len(b) for b in ast_results)
            live.done(f"AST done: {ast_total} finding(s) from {len(ast_targets)} file(s)")

        for batch in ast_results:
            all_findings.extend(batch)

    # ── 4. Classify + deduplicate ───────────────────────────────────────
    all_findings = classify(all_findings)
    print_ok(f"classified: {len(all_findings)} finding(s) after dedup", phase="semantic")

    # ── 4b. Auto-triage ─────────────────────────────────────────────────
    # Walk every finding and mark `verdict = real | verify | fp` so the
    # HTML report and REPL can surface the actionable ones up front.
    try:
        from auto_triage import triage_findings
        counts = triage_findings(all_findings)
        print_ok(
            f"triage: [bright_green]{counts.get('real', 0)} real[/]  "
            f"[bright_white]{counts.get('verify', 0)} verify[/]  "
            f"[dim]{counts.get('fp', 0)} fp[/]",
            phase="semantic",
        )
    except Exception as e:
        print_warn(f"auto-triage failed: {e}  (continuing without verdicts)", phase="warn")

    # ── 4b. LLM verification (opt-in via --verify) ──────────────────────
    if args.verify:
        try:
            from verifier import verify_findings, attach_verification_to_findings
        except ImportError:
            print_progress("⚠  Verifier module missing -- skipping verification")
        else:
            import os as _os
            if not _os.getenv("ANTHROPIC_API_KEY"):
                print_progress("⚠  ANTHROPIC_API_KEY not set -- skipping --verify")
            else:
                # Build source map for verifier code-window extraction
                sources_by_url = {r.url: r.content for r in js_results}
                n_candidates = sum(1 for f in all_findings
                                   if f.category.startswith("semantic:")
                                   and f.severity in ("critical","high"))
                cap = min(n_candidates, args.verify_max)
                print_progress(
                    f"LLM-verifying top {cap} semantic findings via Claude..."
                )
                vresults = await verify_findings(
                    all_findings, sources_by_url,
                    max_findings=args.verify_max,
                    model=args.verify_model,
                )
                attach_verification_to_findings(all_findings, vresults)
                # Count outcomes
                from collections import Counter
                vcounts = Counter()
                for v in vresults.values():
                    vcounts[v["verdict"]] += 1
                if vcounts:
                    summary = ", ".join(f"{k}={v}" for k,v in vcounts.most_common())
                    print_progress(f"Verifier results: {summary}")
                else:
                    print_progress("Verifier produced no results")

    # ── 5. Runtime (Playwright) ─────────────────────────────────────────
    rt_findings = []
    if args.runtime:
        if not PLAYWRIGHT_AVAILABLE:
            print_progress("⚠  Playwright not installed -- skipping runtime analysis")
            print_progress("   Install: pip install playwright && playwright install chromium")
        else:
            print_progress("Launching Playwright for runtime analysis...")
            rt_findings = await run_runtime(
                target=args.url,
                auth_headers=auth_headers,
                headless=not args.no_headless,
                wait_ms=args.wait_ms,
            )
            print_progress(f"Runtime captured {len(rt_findings)} unique requests")

    # ── 6. Diff mode ────────────────────────────────────────────────────
    diff = None
    if args.diff:
        print_progress("Computing diff against last scan...")
        engine = DiffEngine(db_path=args.db)
        scan_id = engine.start_scan(args.url)
        js_urls = [r.url for r in js_results]
        engine.record_js_files(scan_id, js_urls)
        engine.record_findings(scan_id, all_findings)
        diff = engine.diff(args.url, scan_id, all_findings, js_urls)
        engine.finish_scan(scan_id, len(js_results), len(all_findings))
        engine.close()
        print_diff_summary(diff)

    # ── 7. Print terminal output ─────────────────────────────────────────
    new_fp_set = None
    if diff and not diff.get("is_first_scan"):
        new_fp_set = {f.source_url for f in diff.get("new_findings", [])}

    print_section("FINDINGS", count=len(all_findings), color="bright_red")
    print_findings(all_findings, diff_new=new_fp_set, show_all=args.show_all, top=args.top)

    # Auto-grouped attack-surface panels (backends, admin, auth, sinks)
    print_attack_surface(all_findings)

    if rt_findings:
        print_runtime_findings(rt_findings)

    elapsed = time.time() - start

    # ── 8. Export ────────────────────────────────────────────────────────
    rt_url_list = [r.url for r in rt_findings]
    artifacts: dict[str, str] = {}

    if args.output:
        out_path = Path(args.output)
    else:
        out_path = build_output_filename(args.url, "json")

    export_json(args.url, all_findings, rt_findings, diff, out_path)
    print_ok(f"json artifact: [cyan]{out_path}[/]", phase="report")
    artifacts["json"] = str(out_path)

    if args.markdown:
        md_path = Path(args.markdown) if args.markdown != "auto" else out_path.with_suffix(".md")
        export_markdown(args.url, all_findings, rt_findings, md_path)
        print_ok(f"markdown artifact: [cyan]{md_path}[/]", phase="report")
        artifacts["markdown"] = str(md_path)

    if args.html:
        html_path = (Path(args.html) if (isinstance(args.html, str) and args.html != "auto")
                     else out_path.with_suffix(".html"))
        js_urls_for_html = [r.url for r in js_results]
        if args.html_legacy:
            # Old severity-sorted dump for anyone who prefers it.
            export_html(args.url, all_findings, rt_findings, js_urls_for_html, diff, html_path)
            print_ok(f"html artifact (legacy): [cyan]{html_path}[/]", phase="report")
        else:
            # New triage view -- verdict tabs, action lines, evidence boxes.
            from triage_report import export_triage_html
            export_triage_html(args.url, all_findings, rt_findings, js_urls_for_html, diff, html_path)
            print_ok(f"html artifact (triage): [cyan]{html_path}[/]", phase="report")
        artifacts["html"] = str(html_path)

    if args.per_file_reports:
        try:
            from file_reports import write_per_file_reports
            import classifier as _classifier
        except ImportError:
            print_warn("per-file reports module missing", phase="report")
        else:
            reports_dir = Path(args.per_file_reports) if args.per_file_reports != "auto" \
                          else out_path.parent / f"{out_path.stem}_files"
            result = write_per_file_reports(
                target=args.url,
                findings=all_findings,
                summaries=_classifier.SUMMARIES,
                out_dir=reports_dir,
            )
            print_ok(f"per-file reports: {result['written']} → [cyan]{reports_dir}[/]", phase="report")
            artifacts["per-file"] = str(reports_dir)

    # ── 9. Burp integration ──────────────────────────────────────────────
    if args.burp:
        print_progress(f"pushing endpoints to burp ([cyan]{args.burp}[/])", phase="info")
        result = await push_to_burp(all_findings, rt_url_list, burp_url=args.burp)
        print_ok(f"burp: {result['sent']} endpoint(s) pushed", phase="info")

    # ── 10. Hunt journal ─────────────────────────────────────────────────
    if args.journal:
        append_to_journal(args.url, all_findings, Path(args.journal), diff)
        print_ok(f"journal appended: [cyan]{args.journal}[/]", phase="info")
        artifacts["journal"] = str(args.journal)

    # ── 11. Final summary + operator prompt ──────────────────────────────
    print_summary(args.url, len(js_results), all_findings, elapsed)
    print_operator_prompt(artifacts)

    # ── 12. Operator REPL (interactive post-scan console) ────────────────
    # Skip if --no-repl, if stdout/stdin isn't a TTY (piped or redirected),
    # or if there are no findings to triage.
    if not args.no_repl and sys.stdin.isatty() and sys.stdout.isatty() and all_findings:
        try:
            from repl import start_repl
            from reporter import console as _reporter_console
            start_repl(args.url, all_findings, js_results, console=_reporter_console)
        except Exception as e:
            # REPL is opt-in nice-to-have; never let it crash the scan
            print(f"  [!] REPL failed to start: {e}", file=sys.stderr)

    return 0 if not all_findings else 1


def cli():
    parser = argparse.ArgumentParser(
        prog="kx",
        description="kx -- JS Intelligence Extractor for bug bounty & pentest",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  kx -u https://target.com
  kx -u https://target.com --auth "Cookie: session=abc123" --runtime --diff
  kx -u https://target.com --burp http://127.0.0.1:1337 --journal ~/bugbounty/hunt_journal.md
  kx -u https://target.com --depth 8 --concurrency 15 --no-ast
        """,
    )

    # Target
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("--scope", help="Comma-separated allowed domains (e.g. target.com,cdn.target.com)")

    # Auth
    parser.add_argument(
        "--auth",
        help='Auth header(s). Format: "Cookie: session=abc;; Authorization: Bearer token"',
    )

    # Crawl tuning
    parser.add_argument("--depth",       type=int,   default=5,   help="Max recursion depth (default: 5)")
    parser.add_argument("--concurrency", type=int,   default=8,   help="Concurrent requests (default: 8)")
    parser.add_argument("--delay",       type=float, default=0.3, help="Delay between requests in seconds (default: 0.3)")
    parser.add_argument(
        "--no-source-maps", action="store_true",
        help="Disable .js.map fetching and source reconstruction",
    )
    parser.add_argument(
        "--sourcemap-noise", action="store_true",
        help="Include third-party library sources when reconstructing from sourcemaps (very noisy)",
    )
    parser.add_argument(
        "--insecure", "-k", action="store_true",
        help="Skip SSL certificate verification (like curl -k). Use for targets "
             "with broken cert chains -- banks, gov portals, internal apps with "
             "self-signed certs. Required if you see CERTIFICATE_VERIFY_FAILED.",
    )

    # Analysis modes
    parser.add_argument("--no-ast",    action="store_true", help="Skip Node.js AST analysis")
    parser.add_argument(
        "--ast-limit",     type=int, default=60,
        help="Max JS files to AST-parse (default: 60). Tier 1: files static "
             "extraction already hit. Tier 2: largest remaining files.",
    )
    parser.add_argument(
        "--crawl-limit",   type=int, default=500,
        help="Max resources to fetch during crawl (default: 500). Big SPAs "
             "can generate thousands of code-split chunks; the interesting "
             "logic is in the first few hundred. Use 0 for unlimited.",
    )
    parser.add_argument(
        "--top",           type=int, default=None,
        help="Cap the number of finding records printed (per severity tier).",
    )
    parser.add_argument("--runtime",   action="store_true", help="Enable Playwright runtime analysis")
    parser.add_argument("--no-headless", action="store_true", help="Show browser window (debug mode)")
    parser.add_argument("--wait-ms",   type=int, default=5000, help="Runtime wait time in ms (default: 5000)")
    parser.add_argument(
        "--show-all", action="store_true",
        help="Show every finding instead of collapsing duplicates across files",
    )
    parser.add_argument(
        "--no-repl", action="store_true",
        help="Don't drop into the interactive operator console after the scan",
    )
    parser.add_argument(
        "--verify", action="store_true",
        help="Send top semantic findings to Claude for verification + PoC generation (requires ANTHROPIC_API_KEY)",
    )
    parser.add_argument(
        "--verify-max", type=int, default=25,
        help="Max findings to LLM-verify per run (default: 25, hard cap on cost)",
    )
    parser.add_argument(
        "--verify-model", default="claude-sonnet-4-5",
        help="Anthropic model name for verification (default: claude-sonnet-4-5)",
    )

    # Diff mode
    parser.add_argument("--diff", action="store_true", help="Compare with last scan and highlight new findings")
    parser.add_argument("--db",   default=None, help="Path to state DB (default: ~/.kx/state.db)")

    # Output
    parser.add_argument("-o", "--output",   default=None,   help="JSON output path (default: auto-named)")
    parser.add_argument("--markdown",       nargs="?", const="auto", help="Also export Markdown report")
    parser.add_argument("--html",           nargs="?", const="auto", help="Also export HTML report (triage view by default)")
    parser.add_argument("--html-legacy",     action="store_true", help="Use the old severity-sorted HTML layout instead of the triage view")
    parser.add_argument(
        "--per-file-reports", nargs="?", const="auto", default=None,
        help="Write one Markdown 'hunter's notes' per JS file to a directory "
             "(default: <output>_files/)",
    )

    # Integrations
    parser.add_argument("--burp",    default=None, help="Burp REST API URL (e.g. http://127.0.0.1:1337)")
    parser.add_argument("--journal", default=None, help="Path to hunt_journal.md to append findings")

    args = parser.parse_args()

    # Validate URL
    parsed = urlparse(args.url)
    if not parsed.scheme or not parsed.netloc:
        parser.error(f"Invalid URL: {args.url}")

    sys.exit(asyncio.run(main(args)))


if __name__ == "__main__":
    cli()
