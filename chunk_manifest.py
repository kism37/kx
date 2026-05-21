"""
kx -- Chunk-manifest resolver

Lazy-loaded route chunks are the kx-shaped blind spot: the entry bundle
references them by numeric or hashed ID, but they're only fetched if you
click the right link in the SPA. We don't want to wait for a click.

This module parses the entry bundle and extracts every chunk filename it
knows about, regardless of whether the running app would ever load it.

Supports the three big bundler shapes:

  • Webpack 4/5:
      __webpack_require__.f.j = (id, p) => {
        ...
        return ({"123":"abc","124":"def"}[id]+".js")...
      }

    Or as a hash map:
      e[id] = ({
        4823: "ChunkName",
      }[id] || id) + "." + ({
        4823: "abc123",
      }[id] || id) + ".chunk.js"

  • Vite/Rollup:
      const __vite__mapDeps = (i) => i.map(i => ([
        "assets/Foo-abc.js",
        "assets/Bar-def.js",
      ])[i])

  • Next.js: chunks are declared in an inline JSON object near the top.

This is regex-based on purpose. Building a full webpack-runtime parser
would be more accurate but radically slower and the regex hits the common
cases in production bundles with very few false positives. Anything that
doesn't end in .js gets dropped at the consumer side.
"""

import re
from urllib.parse import urljoin, urlparse


# ─── Vite / Rollup ──────────────────────────────────────────────────────────
# Vite emits a function like:
#   const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=[
#     "assets/Aa-DxYz.js",
#     "assets/Bb-EeFf.js",
#     ...
#   ])))=>i.map(i=>d[i]);
# We look for any array literal whose elements are all "assets/...js" strings.
_VITE_DEPS_ARRAY = re.compile(
    r'(?:m\.f\s*=\s*|__vite__mapDeps[^=]*=[^=]*=\s*)\[\s*((?:"[^"]+\.js"\s*,?\s*){2,})\]'
)

# Looser fallback: any array of "assets/X.js" string literals
_VITE_ASSET_LIST = re.compile(
    r'\[\s*((?:"(?:[^"\\]|\\.)*\.js"\s*,?\s*){2,})\]'
)
_VITE_ASSET_STR = re.compile(r'"((?:[^"\\]|\\.)*?\.(?:m?js|cjs))"')


# ─── Webpack ────────────────────────────────────────────────────────────────
# Webpack 5 produces a chunk-filename function. The filename template often
# contains numeric IDs mapped to short basename strings:
#   (({4823: "FooPage"}[a]||a) + "." + ({4823:"abc1234"}[a]||"") + ".js")
# We extract two object literals (id→name and id→hash) from such expressions.
_WEBPACK_NAME_MAP = re.compile(
    # Match a `{NUM: "STRING", NUM: "STRING", ...}` object literal where keys are numbers
    r'\{(\s*(?:"?\d+"?\s*:\s*"[^"]+"\s*,?\s*){2,})\}'
)
_WEBPACK_ENTRY = re.compile(r'"?(\d+)"?\s*:\s*"([^"]+)"')

# Webpack also frequently has the literal chunk filename template, e.g.
#   "static/chunks/" + ({...}[a]||a) + "-" + ({...}[a]||"") + ".js"
_WEBPACK_TEMPLATE = re.compile(r'"((?:static/chunks/|chunks/|js/|assets/)[^"]*?)"\s*\+')


# ─── Next.js ────────────────────────────────────────────────────────────────
# Next.js page chunks are typically referenced as:
#   /_next/static/chunks/pages/admin-abc123.js
# We catch a broad pattern that's well-anchored.
_NEXT_CHUNK = re.compile(
    r'["\'`](/_next/static/(?:chunks|css|media)/[^"\'`\s]+\.(?:js|mjs))["\'`]'
)


# ─── Direct chunk references ────────────────────────────────────────────────
# Catchall for hashed asset filenames inside any quoted string.
# Matches: "assets/Foo-Abc1234.js", "static/chunks/8765-abc123.js", etc.
_HASHED_CHUNK = re.compile(
    r'["\'`]((?:[\w./-]+/)?(?:[\w.-]+-[A-Za-z0-9_-]{6,}|chunk[\w.-]*|[a-f0-9]{8,})\.(?:m?js|cjs))["\'`]'
)


def extract_chunk_filenames(content: str) -> set[str]:
    """
    Pull every chunk-like filename out of an entry-bundle's source.

    Returns a set of filename strings (relative -- caller resolves against the
    bundle's base URL). Filenames are de-duplicated but not validated.
    Anything obviously not a JS path is filtered out.
    """
    found: set[str] = set()

    # 1. Vite/Rollup array forms
    for m in _VITE_DEPS_ARRAY.finditer(content):
        for s in _VITE_ASSET_STR.finditer(m.group(1)):
            found.add(s.group(1))
    # Fallback: any sufficiently large all-JS-string array literal
    if not found:
        for m in _VITE_ASSET_LIST.finditer(content):
            # Filter: every string in the array must end in .js
            block = m.group(1)
            strings = re.findall(r'"((?:[^"\\]|\\.)*?)"', block)
            if not strings:
                continue
            if all(s.endswith((".js", ".mjs", ".cjs")) for s in strings):
                found.update(strings)

    # 2. Webpack name maps → reconstruct candidate filenames
    name_maps = []
    for m in _WEBPACK_NAME_MAP.finditer(content):
        entries = dict(_WEBPACK_ENTRY.findall(m.group(1)))
        if len(entries) >= 2:
            name_maps.append(entries)

    # Identify the most likely (id → name) and (id → hash) maps by content
    # signature. We rely on a tight distinction:
    #   - HASH: lowercase alnum with optional dashes, no uppercase
    #     letters, no path separators, no dots; typically 6-24 chars
    #     (e.g. "abc12345", "9f8a7b6c", "K3iI8j-Dw").
    #   - NAME: contains uppercase OR is mostly letters (identifier-like)
    #     (e.g. "AdminPage", "auth_login", "vendor-react").
    def _looks_hash_value(v: str) -> bool:
        if len(v) < 6 or len(v) > 24:
            return False
        if not re.fullmatch(r"[a-z0-9_-]+", v):
            return False
        # Must contain at least one digit (real hashes are alnum mixes)
        if not re.search(r"\d", v):
            return False
        return True

    def _looks_name_value(v: str) -> bool:
        # Has uppercase, or has a typical name separator, or is short and
        # all-letters
        if re.search(r"[A-Z]", v):
            return True
        if re.fullmatch(r"[a-z][a-z0-9_-]*", v) and not re.search(r"\d", v):
            return True
        return False

    id_to_name = {}
    id_to_hash = {}
    for nm in name_maps:
        values = list(nm.values())
        hash_ratio = sum(_looks_hash_value(v) for v in values) / len(values)
        name_ratio = sum(_looks_name_value(v) for v in values) / len(values)
        if hash_ratio >= 0.8 and not id_to_hash:
            id_to_hash = nm
        elif name_ratio >= 0.6 and not id_to_name:
            id_to_name = nm

    # Try to reconstruct: name-hash.js per id present in BOTH maps.
    common_ids = set(id_to_name.keys()) & set(id_to_hash.keys())
    for cid in common_ids:
        nm = id_to_name[cid]
        hh = id_to_hash[cid]
        # Strip path separators from name; keep alphanum + dashes
        safe_name = re.sub(r"[^\w./-]", "", nm)
        # Try a few common templates -- always with a path prefix so we don't
        # produce naked filenames that resolve to the wrong location.
        for tmpl in (
            f"static/chunks/{safe_name}-{hh}.js",
            f"static/chunks/{cid}-{hh}.js",
            f"_next/static/chunks/{safe_name}-{hh}.js",
            f"_next/static/chunks/pages/{safe_name}-{hh}.js",
            f"assets/{safe_name}-{hh}.js",
            f"js/{safe_name}.{hh}.js",
            f"chunks/{safe_name}.{hh}.js",
        ):
            found.add(tmpl)

    # 3. Next.js explicit chunk paths
    for m in _NEXT_CHUNK.finditer(content):
        found.add(m.group(1))

    # 4. Hashed chunks (catch-all)
    for m in _HASHED_CHUNK.finditer(content):
        path = m.group(1)
        # Filter obvious non-chunk garbage: skip if it's a node_modules path,
        # CDN, or a relative parent reference
        if path.startswith("..") or "node_modules/" in path:
            continue
        # Sanity-cap length
        if len(path) > 200:
            continue
        found.add(path)

    # 5. Filter out anything that doesn't look like a real file path
    cleaned: set[str] = set()
    for path in found:
        if " " in path or "\n" in path:
            continue
        if not re.search(r"[\w/-]\.(m?js|cjs)$", path):
            continue
        cleaned.add(path)
    return cleaned


def resolve_chunks_against_base(chunks: set[str], base_url: str,
                                 origin: str) -> set[str]:
    """
    Convert raw chunk paths into absolute URLs.

    Uses several resolution strategies and emits each one for each chunk:
      1. urljoin against the entry bundle URL  →  Vite-style "assets/X.js"
         relative refs.
      2. urljoin against the entry bundle's parent directory
      3. urljoin against the site origin       →  Next.js-style absolute
         "/_next/static/X.js" refs.

    The crawler will dedupe and 404s will be silently ignored.
    """
    out: set[str] = set()
    parent = base_url.rsplit("/", 1)[0] + "/"
    grand_parent = parent.rstrip("/").rsplit("/", 1)[0] + "/"
    for path in chunks:
        for base in (base_url, parent, grand_parent, origin + "/"):
            try:
                out.add(urljoin(base, path))
            except Exception:
                pass
    return out
