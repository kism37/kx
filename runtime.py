"""
kx -- Runtime Analyser (Playwright)
Hooks fetch, XMLHttpRequest, and WebSocket constructors.
Captures all runtime network requests and dynamic URL construction.
"""

import asyncio
import json
from dataclasses import dataclass
from typing import Optional

try:
    from playwright.async_api import async_playwright, Page, BrowserContext
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


# JS injected into the page before any script runs
_HOOK_SCRIPT = """
(() => {
  window.__kx_findings = [];

  function record(type, url, meta) {
    window.__kx_findings.push({ type, url, meta, ts: Date.now() });
  }

  // Hook fetch
  const _fetch = window.fetch;
  window.fetch = function(input, init) {
    const url = typeof input === 'string' ? input : input?.url || String(input);
    record('fetch', url, {
      method: (init?.method || 'GET').toUpperCase(),
      headers: init?.headers || {},
    });
    return _fetch.apply(this, arguments);
  };

  // Hook XMLHttpRequest
  const _open = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url) {
    record('xhr', url, { method: method.toUpperCase() });
    return _open.apply(this, arguments);
  };

  // Hook WebSocket
  const _WS = window.WebSocket;
  window.WebSocket = function(url, protocols) {
    record('websocket', url, { protocols });
    return new _WS(url, protocols);
  };
  Object.setPrototypeOf(window.WebSocket, _WS);

  // Hook navigator.sendBeacon
  const _beacon = navigator.sendBeacon.bind(navigator);
  navigator.sendBeacon = function(url, data) {
    record('beacon', url, {});
    return _beacon(url, data);
  };

  // Hook EventSource (SSE)
  const _ES = window.EventSource;
  if (_ES) {
    window.EventSource = function(url, init) {
      record('eventsource', url, {});
      return new _ES(url, init);
    };
  }
})();
"""


@dataclass
class RuntimeFinding:
    type: str         # fetch | xhr | websocket | beacon | eventsource
    url: str
    method: str = "GET"
    headers: dict = None
    source: str = "runtime"


async def _collect_page(
    context: "BrowserContext",
    url: str,
    wait_ms: int,
    auth_headers: dict,
) -> list[RuntimeFinding]:
    """Load a single page and collect runtime network events."""
    page: Page = await context.new_page()

    # Inject hook before any page script runs
    await page.add_init_script(_HOOK_SCRIPT)

    # Set auth headers on all requests
    if auth_headers:
        await page.set_extra_http_headers(auth_headers)

    findings: list[RuntimeFinding] = []

    # Also capture via CDP-level network interception
    async def on_request(request):
        resource_type = request.resource_type
        if resource_type in ("fetch", "xhr", "websocket"):
            findings.append(RuntimeFinding(
                type=resource_type,
                url=request.url,
                method=request.method,
                headers=dict(request.headers),
                source="network",
            ))

    page.on("request", on_request)

    try:
        await page.goto(url, wait_until="networkidle", timeout=30_000)
        await page.wait_for_timeout(wait_ms)
    except Exception:
        pass

    # Extract hook-captured findings
    try:
        raw = await page.evaluate("() => window.__kx_findings || []")
        for item in raw:
            findings.append(RuntimeFinding(
                type=item.get("type", "unknown"),
                url=item.get("url", ""),
                method=item.get("meta", {}).get("method", "GET"),
                headers=item.get("meta", {}).get("headers", {}),
                source="hook",
            ))
    except Exception:
        pass

    await page.close()
    return findings


async def run_runtime(
    target: str,
    auth_headers: dict | None = None,
    headless: bool = True,
    wait_ms: int = 5000,
) -> list[RuntimeFinding]:
    """
    Launch Playwright, visit target, return all intercepted runtime requests.
    """
    if not PLAYWRIGHT_AVAILABLE:
        return []

    auth_headers = auth_headers or {}
    all_findings: list[RuntimeFinding] = []

    async with async_playwright() as pw:
        browser = await pw.chromium.launch(headless=headless)
        context = await browser.new_context(
            ignore_https_errors=True,
            user_agent=(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/124.0.0.0 Safari/537.36"
            ),
        )

        results = await _collect_page(context, target, wait_ms, auth_headers)
        all_findings.extend(results)

        await context.close()
        await browser.close()

    # Deduplicate by (type, url, method)
    seen: set[tuple] = set()
    deduped = []
    for f in all_findings:
        key = (f.type, f.url, f.method)
        if key not in seen:
            seen.add(key)
            deduped.append(f)

    return deduped
