"""
kx -- Async HTTP crawler
Fetches HTML pages and recursively discovers all JS files
"""

import asyncio
import re
import time
from urllib.parse import urljoin, urlparse, urlunparse
from typing import Optional

import httpx

# Manifest resolver -- discovers lazy-route chunks referenced by entry bundles
from chunk_manifest import extract_chunk_filenames, resolve_chunks_against_base
# Source-map reconstructor -- recovers original sources from .js.map files
from sourcemap_recover import reconstruct_from_sourcemap

# Patterns to extract JS references from HTML and JS files
_SCRIPT_SRC      = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)
_IMPORT_STATIC   = re.compile(r'(?:import|from)\s+["\']([^"\']+\.js[^"\']*)["\']')
_REQUIRE_CALL    = re.compile(r'require\s*\(\s*["\']([^"\']+\.js[^"\']*)["\']')
_DYNAMIC_IMPORT  = re.compile(r'import\s*\(\s*["\']([^"\']+)["\']')
_WEBPACK_CHUNK   = re.compile(r'["\'`]([^"\'`]*chunk[^"\'`]*\.js[^"\'`]*)["\'\`]', re.I)
_VITE_ASSET      = re.compile(r'["\'`]([^"\'`]*/assets/[A-Za-z0-9.\-_]+\.js)["\'\`]')
_NEXT_BUILD      = re.compile(r'["\'`](/_next/static/[^\s"\'`]+\.js)["\'\`]')
_NUXT_BUILD      = re.compile(r'["\'`](/_nuxt/[^\s"\'`]+\.js)["\'\`]')
_LAZY_ROUTE      = re.compile(r'["\'`]([^"\'`]+\.(js|mjs|cjs))["\'\`]')
_SOURCEMAP       = re.compile(r'//[#@]\s*sourceMappingURL=([^\s]+)')

DEFAULT_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept-Encoding": "gzip, deflate, br",
}

# Browser-like headers for the initial document request. Many WAFs/servers
# (Cloudflare, AWS WAF, simple bot filters) check the Accept header and
# Sec-Fetch-* on the navigation request specifically.
NAVIGATION_HEADERS = {
    **DEFAULT_HEADERS,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-User": "?1",
    "Sec-Fetch-Dest": "document",
    "Upgrade-Insecure-Requests": "1",
}

# Signals that a response is a bot-challenge / WAF intercept, not the real page.
_CHALLENGE_INDICATORS = (
    "cf-mitigated",
    "cf-chl-bypass",
    "challenge-platform",
    "Just a moment...",
    "Checking your browser before accessing",
    "Please enable JavaScript and cookies",
    "<title>Attention Required",
    "ddos-guard",
    "_Incapsula_Resource",
)

MAX_JS_SIZE = 10 * 1024 * 1024  # 10 MB cap per file


class CrawlResult:
    __slots__ = ("url", "content", "content_type", "status", "source_maps")

    def __init__(self, url, content, content_type, status, source_maps=None):
        self.url = url
        self.content = content
        self.content_type = content_type
        self.status = status
        self.source_maps = source_maps or []


class Crawler:
    def __init__(
        self,
        target: str,
        auth_headers: dict | None = None,
        max_depth: int = 5,
        concurrency: int = 8,
        delay: float = 0.3,
        timeout: float = 15.0,
        scope_domains: list[str] | None = None,
        recover_source_maps: bool = True,
        include_sourcemap_noise: bool = False,
        max_resources: int | None = None,
        verify_ssl: bool = True,
    ):
        self.target = target.rstrip("/")
        self.origin = self._origin(target)
        self.auth_headers = auth_headers or {}
        self.max_depth = max_depth
        self.concurrency = concurrency
        self.delay = delay
        self.timeout = timeout
        self.scope_domains = scope_domains
        self.recover_source_maps = recover_source_maps
        self.include_sourcemap_noise = include_sourcemap_noise
        # Hard cap on number of resources fetched. None = unlimited.
        # Big SPAs (Vite/Vue/Next with route-based code splitting) can
        # generate thousands of chunks. The interesting logic is in the
        # first N by discovery order; the rest is icons, vendor splits,
        # and unused lazy-loaded routes. Cap protects against runaway
        # crawls that take 10+ minutes for diminishing returns.
        self.max_resources = max_resources
        # Disabling SSL verification is required for targets with broken cert
        # chains -- banks and government portals often present a leaf cert
        # without bundling the intermediate CA. Browsers repair via AIA;
        # Python's ssl module doesn't. With `--insecure`, the crawler
        # behaves like `curl -k`.
        self.verify_ssl = verify_ssl
        self.cap_reached: bool = False  # set to True once we stop accepting

        self._visited: set[str] = set()
        self._semaphore: asyncio.Semaphore = asyncio.Semaphore(concurrency)
        self._results: list[CrawlResult] = []
        self._js_queue: list[tuple[str, int]] = []  # (url, depth)
        # Counter populated during the recovery phase
        self.sourcemap_recovered: int = 0
        # Diagnostic state -- populated as the crawl progresses so the CLI
        # can explain WHY a scan produced no results.
        self.fetch_errors: list[dict] = []  # [{url, reason, status?}]
        self.root_status: int | None = None
        self.root_reason: str | None = None

    # ------------------------------------------------------------------
    def _origin(self, url: str) -> str:
        p = urlparse(url)
        return f"{p.scheme}://{p.netloc}"

    def _normalize(self, href: str, base: str) -> str | None:
        """Resolve relative URL and normalise (strip fragment/query noise)."""
        try:
            full = urljoin(base, href.strip())
            p = urlparse(full)
            # drop anchors, keep query (needed for some chunk loaders)
            norm = urlunparse((p.scheme, p.netloc, p.path, "", p.query, ""))
            return norm if p.scheme in ("http", "https") else None
        except Exception:
            return None

    def _in_scope(self, url: str) -> bool:
        if self.scope_domains:
            host = urlparse(url).netloc
            return any(host == d or host.endswith("." + d) for d in self.scope_domains)
        # Default: same origin + same root domain (e.g. CDN subdomains)
        host = urlparse(url).netloc
        origin_host = urlparse(self.origin).netloc
        # strip www / port
        def bare(h):
            # Strip "www." prefix correctly (.lstrip on a multi-char arg
            # strips *any combination* of those chars; use a real prefix removal).
            host_only = h.split(":")[0]
            if host_only.startswith("www."):
                host_only = host_only[4:]
            return host_only
        return bare(host) == bare(origin_host) or url.startswith(self.origin)

    def _is_js(self, url: str, content_type: str) -> bool:
        if any(url.endswith(ext) for ext in (".js", ".mjs", ".cjs")):
            return True
        return "javascript" in content_type or "ecmascript" in content_type

    # ------------------------------------------------------------------
    async def _fetch(self, client: httpx.AsyncClient, url: str,
                     *, is_navigation: bool = False) -> httpx.Response | None:
        async with self._semaphore:
            if self.delay:
                await asyncio.sleep(self.delay)
            try:
                headers = NAVIGATION_HEADERS if is_navigation else None
                r = await client.get(url, follow_redirects=True, headers=headers)
                if r.status_code >= 400:
                    self.fetch_errors.append({
                        "url": url,
                        "status": r.status_code,
                        "reason": f"HTTP {r.status_code}",
                        "body_preview": (r.text or "")[:200].strip(),
                    })
                return r
            except httpx.ConnectError as e:
                self.fetch_errors.append({"url": url, "reason": f"connect error: {e}"})
            except httpx.TimeoutException as e:
                self.fetch_errors.append({"url": url, "reason": f"timeout: {e}"})
            except httpx.TooManyRedirects as e:
                self.fetch_errors.append({"url": url, "reason": f"too many redirects: {e}"})
            except httpx.HTTPError as e:
                self.fetch_errors.append({"url": url, "reason": f"http error: {type(e).__name__}: {e}"})
            except Exception as e:
                self.fetch_errors.append({"url": url, "reason": f"{type(e).__name__}: {e}"})
            return None

    # ------------------------------------------------------------------
    def _extract_js_urls(self, content: str, base_url: str) -> set[str]:
        """Pull every JS reference from HTML or JS content."""
        raw: set[str] = set()

        for pattern in (
            _SCRIPT_SRC, _IMPORT_STATIC, _REQUIRE_CALL,
            _DYNAMIC_IMPORT, _WEBPACK_CHUNK, _VITE_ASSET,
            _NEXT_BUILD, _NUXT_BUILD,
        ):
            for m in pattern.finditer(content):
                raw.add(m.group(1))

        # Lazy route / generic .js refs -- noisier, filter carefully
        for m in _LAZY_ROUTE.finditer(content):
            href = m.group(1)
            if href.startswith("http") or href.startswith("/"):
                raw.add(href)

        resolved: set[str] = set()
        for href in raw:
            norm = self._normalize(href, base_url)
            if norm and norm not in self._visited and self._in_scope(norm):
                resolved.add(norm)
        return resolved

    def _extract_source_maps(self, content: str, base_url: str) -> list[str]:
        maps = []
        for m in _SOURCEMAP.finditer(content):
            ref = m.group(1).strip()
            if not ref.startswith("data:"):
                norm = self._normalize(ref, base_url)
                if norm:
                    maps.append(norm)
        return maps

    # ------------------------------------------------------------------
    async def _crawl_url(
        self,
        client: httpx.AsyncClient,
        url: str,
        depth: int,
    ) -> None:
        if url in self._visited or depth > self.max_depth:
            return
        # Resource cap: stop accepting new fetches once we hit the limit.
        # The root document (depth=0) and already-queued items still complete
        # to keep behaviour consistent, but new URLs get rejected.
        if self.max_resources is not None and len(self._results) >= self.max_resources and depth > 0:
            if not self.cap_reached:
                self.cap_reached = True
            return
        self._visited.add(url)

        # The initial document request should look like a real browser
        # navigation -- many simple WAFs/bot filters key on the Accept
        # header and Sec-Fetch-* metadata for the navigation request.
        is_nav = (depth == 0)
        resp = await self._fetch(client, url, is_navigation=is_nav)
        if resp is None or resp.status_code >= 400:
            return

        # Detect WAF / bot-challenge interception -- kx might be hitting
        # a JS-challenge page rather than the real app.
        if depth == 0 and resp.text:
            body_sample = resp.text[:4000]
            for indicator in _CHALLENGE_INDICATORS:
                if indicator.lower() in body_sample.lower() or indicator.lower() in str(resp.headers).lower():
                    self.fetch_errors.append({
                        "url": url,
                        "status": resp.status_code,
                        "reason": f"WAF/bot-challenge page detected (matched: {indicator!r})",
                        "body_preview": body_sample[:200].strip(),
                    })
                    # Don't return -- we still record the result so the user
                    # can SEE what got served, but it's flagged.
                    break

        content_type = resp.headers.get("content-type", "")
        # Honour size cap
        content = resp.text[:MAX_JS_SIZE] if len(resp.text) > MAX_JS_SIZE else resp.text

        source_maps = self._extract_source_maps(content, url)
        result = CrawlResult(
            url=url,
            content=content,
            content_type=content_type,
            status=resp.status_code,
            source_maps=source_maps,
        )
        self._results.append(result)

        # Queue discovered JS files for recursive crawl
        discovered = self._extract_js_urls(content, url)

        # ── Chunk-manifest discovery ──
        # On JS responses (especially entry bundles), parse the bundler
        # manifest to surface lazy-route chunks the crawler would otherwise
        # never reach. Limited to depth ≤ 2 because entry bundles are
        # typically loaded at depth 1 from the HTML root.
        if self._is_js(url, content_type) and depth <= 2:
            try:
                raw_chunks = extract_chunk_filenames(content)
                if raw_chunks:
                    manifest_urls = resolve_chunks_against_base(
                        raw_chunks, url, self.origin
                    )
                    for mu in manifest_urls:
                        norm = self._normalize(mu, url)
                        if norm and norm not in self._visited and self._in_scope(norm):
                            discovered.add(norm)
            except Exception:
                # Manifest parsing is best-effort -- never let it break the crawl.
                pass

        tasks = []
        for js_url in discovered:
            if js_url not in self._visited:
                tasks.append(self._crawl_url(client, js_url, depth + 1))

        if tasks:
            await asyncio.gather(*tasks)

    # ------------------------------------------------------------------
    async def _recover_source_maps(self, client: httpx.AsyncClient) -> None:
        """
        Post-crawl phase: fetch every discovered .js.map and append the
        reconstructed original-source files as virtual CrawlResults so
        downstream detectors see them transparently.

        Each reconstructed file gets a synthetic URL
        `sourcemap://<map-url>#<original-path>` for stable identity.
        """
        # Collect unique map URLs across all crawled JS files
        map_urls: set[str] = set()
        for r in self._results:
            for mu in (r.source_maps or []):
                map_urls.add(mu)

        if not map_urls:
            return

        async def _fetch_and_reconstruct(murl: str):
            resp = await self._fetch(client, murl)
            if resp is None or resp.status_code >= 400:
                return []
            text = resp.text
            if len(text) > MAX_JS_SIZE * 4:   # maps can be big; cap looser than JS
                text = text[:MAX_JS_SIZE * 4]
            try:
                files = reconstruct_from_sourcemap(
                    text, murl,
                    include_noise=self.include_sourcemap_noise,
                )
            except Exception:
                return []
            recovered = []
            for rf in files:
                if rf.virtual_url in self._visited:
                    continue
                self._visited.add(rf.virtual_url)
                recovered.append(CrawlResult(
                    url=rf.virtual_url,
                    content=rf.content,
                    content_type="application/typescript; sourcemap-recovered",
                    status=200,
                    source_maps=[],
                ))
            return recovered

        results = await asyncio.gather(*[_fetch_and_reconstruct(m) for m in map_urls])
        for batch in results:
            self._results.extend(batch)
            self.sourcemap_recovered += len(batch)

    # ------------------------------------------------------------------
    async def crawl(self) -> list[CrawlResult]:
        """Entry point. Returns all fetched pages/JS files."""
        headers = {**DEFAULT_HEADERS, **self.auth_headers}

        async with httpx.AsyncClient(
            headers=headers,
            timeout=self.timeout,
            verify=self.verify_ssl,
            limits=httpx.Limits(
                max_connections=self.concurrency * 2,
                max_keepalive_connections=self.concurrency,
            ),
        ) as client:
            # Start from the target page
            await self._crawl_url(client, self.target, depth=0)
            # Then walk sourcemaps if enabled
            if self.recover_source_maps:
                await self._recover_source_maps(client)

        return self._results

    @property
    def visited_count(self) -> int:
        return len(self._visited)
