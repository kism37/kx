"""
kx -- Source-map reconstructor

When a minified JS file ships a sourcemap (.js.map), it contains the original
source files inline as the `sourcesContent` array. Production deploys ship
these maps ~40% of the time (more often than people think -- Sentry-style
error-monitoring pipelines push teams to keep them in prod).

If we can fetch the map, we can scan the *original* TypeScript / JavaScript
instead of the minified slop. Every detector becomes radically more
effective: variable names are real, comments are present, imports are
clear, and a 50k-line bundle becomes 200 small files.

This module:
  1. Parses a sourcemap (v3 spec, JSON with optional ")]}'\n" prefix).
  2. Pulls every entry of `sourcesContent` into a virtual CrawlResult.
  3. Tags each reconstructed file with a synthetic URL so the rest of the
     pipeline (classifier, reporter, diff store) treats them uniformly.

We intentionally do NOT try to map line numbers from minified back to
original -- that's an O(N log N) per-finding mapping operation we don't need.
We just scan the original source as-is and report findings against the
*original* line numbers (already correct because we're parsing the original
content).
"""

import json
import re
from typing import Iterable
from urllib.parse import urlparse


# Sourcemaps occasionally have a XSSI-protection prefix; strip it.
_XSSI_PREFIX = re.compile(r"^\)\]\}'?\n?")


class ReconstructedFile:
    __slots__ = ("virtual_url", "source_url", "original_path", "content")

    def __init__(self, virtual_url: str, source_url: str,
                 original_path: str, content: str):
        # virtual_url     -- stable, unique identifier we use everywhere
        # source_url      -- the .js.map file we got this from
        # original_path   -- path as recorded in the map (e.g. "src/api/x.ts")
        # content         -- the original source text
        self.virtual_url = virtual_url
        self.source_url = source_url
        self.original_path = original_path
        self.content = content


# Filter: ignore obvious third-party noise reconstructed from sourcemaps.
# Bundlers inline these in production; they generate vast amounts of garbage
# findings (jquery, lodash, react internals, polyfills).
_NOISE_PATH_RE = re.compile(
    r"(^|/)(node_modules|webpack(/|\.)|"
    r"\.pnpm/|\.yarn/|"
    r"vendor[s]?/|polyfills?/|"
    r"(^|/)react(-dom)?/|"
    r"(^|/)lodash(/|\.)|"
    r"(^|/)jquery(/|\.)|"
    r"core-js/|tslib\.|"
    r"regenerator-runtime/|"
    r"@babel/|@swc/|@vue/|@angular/|"
    r"runtime-(core|dom)\.|"
    r"@mui/|@material-ui/|@chakra-ui/|"
    r"@emotion/|@stitches/|"
    r"@floating-ui/|@radix-ui/|"
    r"\.css\.|\.scss\.)",
    re.I,
)


def _is_noise_path(path: str) -> bool:
    """True if this sourcemap-reconstructed path is a third-party library."""
    if not path:
        return True
    return bool(_NOISE_PATH_RE.search(path))


def parse_sourcemap(content: str) -> dict | None:
    """Parse a sourcemap JSON string, returning the dict or None on failure."""
    if not content:
        return None
    cleaned = _XSSI_PREFIX.sub("", content.lstrip())
    try:
        data = json.loads(cleaned)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    return data


def reconstruct_from_sourcemap(
    map_content: str,
    map_url: str,
    *,
    include_noise: bool = False,
) -> list[ReconstructedFile]:
    """
    Pull every original source out of a sourcemap into ReconstructedFile
    objects. `include_noise=False` (default) drops third-party library sources.
    """
    data = parse_sourcemap(map_content)
    if not data:
        return []

    sources = data.get("sources") or []
    sources_content = data.get("sourcesContent") or []
    if not sources_content:
        # The map exists but has no inlined source content. Some maps only
        # reference original files by URL -- we'd need to fetch them, which
        # is rarely worth it because if they were public we'd be crawling
        # them already.
        return []

    out: list[ReconstructedFile] = []
    # Some maps have a `sourceRoot` prefix
    source_root = data.get("sourceRoot", "") or ""

    for idx, src_path in enumerate(sources):
        if idx >= len(sources_content):
            break
        content = sources_content[idx]
        if content is None or not isinstance(content, str):
            continue
        if not content.strip():
            continue
        full_path = (source_root + src_path) if source_root else src_path
        # Normalize webpack:// and similar protocol prefixes for readability
        clean_path = re.sub(r"^[a-z]+://[^/]*/", "", full_path)
        clean_path = re.sub(r"^/+", "", clean_path)

        if not include_noise and _is_noise_path(clean_path):
            continue

        # Only consider real source files
        if not re.search(r"\.(t|j)sx?$|\.mjs$|\.cjs$|\.vue$|\.svelte$", clean_path):
            continue

        # Synthetic URL for downstream use. Keep the original .js.map URL
        # as the source so the reporter can show provenance.
        virtual_url = f"sourcemap://{map_url}#{clean_path}"
        out.append(ReconstructedFile(
            virtual_url=virtual_url,
            source_url=map_url,
            original_path=clean_path,
            content=content,
        ))

    return out


def reconstruct_many(
    pairs: Iterable[tuple[str, str]],
    *,
    include_noise: bool = False,
) -> list[ReconstructedFile]:
    """Convenience: reconstruct from many (map_url, map_content) pairs."""
    out: list[ReconstructedFile] = []
    for map_url, content in pairs:
        out.extend(reconstruct_from_sourcemap(
            content, map_url, include_noise=include_noise
        ))
    return out
