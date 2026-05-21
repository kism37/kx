"""
kx -- Auto-triage

After classification, walks every finding and assigns a `verdict`:

    real    -- high-confidence true positive (admin paths, IDOR-shaped
              semantics, role enumeration, etc.)
    verify  -- needs human eyes; the default
    fp      -- confidently framework/library noise

The rules are derived from real triage work on production Vue/React/Next
bundles. They're conservative: a false `fp` is worse than a false `verify`,
so we only mark `fp` when context strongly indicates framework internals.

Each finding gains a `verdict_reason` string explaining *why* the call was
made -- visible in the HTML report and REPL so the operator can override.
"""
from __future__ import annotations
import re

# ── Library / framework signatures ─────────────────────────────────────────
# If a finding's source URL or surrounding context matches these signatures,
# we treat it as framework noise unless it's a high-confidence vuln category.

_REACT_DOM_SIGS = re.compile(
    r"dangerouslySetInnerHTML|__html|react-dom|"
    r"ReactCurrentDispatcher|ReactCurrentOwner|"
    r"createElement\(\"div\",\s*null,"
    , re.I,
)
_REDUX_TOOLKIT_SIGS = re.compile(
    r"createAsyncThunk|createSlice|createReducer|"
    r"requestId|fulfilled|rejected|configureStore|"
    r"unwrap.*then|abort.*requestId"
    , re.I,
)
_AXIOS_SIGS = re.compile(
    r"axios|XMLHttpRequest|defaults\.adapter|"
    r"isAxiosError|interceptors\.request|InterceptorManager"
    , re.I,
)
_CORE_JS_SIGS = re.compile(
    r"core-js|zloirock|polyfill|"
    r"WHATWG\s*URL|URL\s*parser|"
    r"AbstractGlobalContext|globalThis"
    , re.I,
)
_NEXT_INTERNAL_SIGS = re.compile(
    r"__NEXT_|next/dist|/_next/static|TurbopackBuildManifest|"
    r"__webpack_require__|webpackChunk|"
    r"NextRouter|useRouter|/ROOT/node_modules"
    , re.I,
)
_VUE_INTERNAL_SIGS = re.compile(
    r"vue@\d|__vue_app__|setupContext|defineComponent|"
    r"VNode|patchProp|isCustomElement"
    , re.I,
)
_TEST_URL_FIXTURES = re.compile(
    r"^https?://(a|x|n|test|host|тест|a@b|user:pass@)/?$|"
    r"^https?://[a-z]{1,3}$"
    , re.I,
)
_W3_NAMESPACES = re.compile(
    r"^https?://www\.w3\.org/"
    r"(2000/svg|1999/xlink|1999/xhtml|2000/xmlns|1998/Math)"
    , re.I,
)
_PUBLIC_CDN_HOSTS = re.compile(
    r"^https?://("
    r"react\.dev|"
    r"reactjs\.org|"
    r"vuejs\.org|"
    r"angular\.io|"
    r"www\.googletagmanager\.com|"
    r"www\.google-analytics\.com|"
    r"cdn\.jsdelivr\.net|"
    r"cdnjs\.cloudflare\.com|"
    r"unpkg\.com|"
    r"polyfill\.io|"
    r"github\.com/(zloirock|facebook|vuejs|reduxjs|microsoft)|"
    r"developers\.google\.com|"
    r"developer\.mozilla\.org|"
    r"caniuse\.com"
    r")"
    , re.I,
)
_IMAGE_CDN_HOSTS = re.compile(
    r"^https?://("
    r"res\.cloudinary\.com|"
    r"images\.unsplash\.com|"
    r"i\.imgur\.com|"
    r"[a-z0-9-]+\.imgix\.net|"
    r"[a-z0-9]+\.animaapp\.com|"
    r"[a-z0-9-]+\.amazonaws\.com/[^/]+/img"
    r")"
    , re.I,
)
_REDUX_ACTION_SUFFIX = re.compile(r"^/(fulfilled|pending|rejected|loading|success|failure)$", re.I)
_NEXT_BUILD_PATH = re.compile(
    r"^/(_next/|_index|_tree|_head|_not-found|_app|_document|"
    r"ROOT/|api/_)"
    , re.I,
)
_AXIOS_LOCALHOST_FALLBACK = re.compile(
    r'window\.location\.href\s*\|\|\s*"https?://localhost"', re.I,
)

# ── Strong positive signals ────────────────────────────────────────────────
# These categories/patterns are almost always worth chasing.

_REAL_CATEGORIES = {
    "semantic:idor",
    "semantic:ssrf",
    "semantic:auth_bypass",
    "semantic:privilege_escalation",
    "semantic:hardcoded_role",
    "semantic:jwt_client_authz",
    "semantic:postmessage_no_origin_check",
    "semantic:storage_token",
    "semantic:websocket_no_auth_in_url",
    "semantic:tainted_sink",
    "secrets",
}

_REAL_NAME_KEYWORDS = re.compile(
    r"admin panel|s3 bucket|password field literal|"
    r"redirect.url field|role/permission|aws access key|"
    r"stripe.+key|api key|jwt secret|impersonation"
    , re.I,
)

_REAL_PATH_KEYWORDS = re.compile(
    r"(^|/)(impersonate|impersonation|control-panel|"
    r"sudo|switch-role|direct-login-link|"
    r"institution-backup|users/destroy|"
    r"force-password-change)"
    , re.I,
)

# Storage tokens -- always worth flagging because they amplify any XSS
_STORAGE_TOKEN_PATTERNS = re.compile(
    r'localStorage\s*\.\s*(get|set)Item\s*\(\s*["\'](token|refresh.?token|access.?token|jwt|bearer)["\']',
    re.I,
)


# ── Verdict rules (run in order; first match wins) ─────────────────────────

def _is_framework_chunk(finding) -> tuple[bool, str]:
    """Examine finding context and source URL to detect framework chunks."""
    blob = (finding.snippet or "") + " " + (finding.context or "") + " " + (finding.source_url or "")
    if _CORE_JS_SIGS.search(blob):
        return True, "core-js polyfill chunk"
    if _REACT_DOM_SIGS.search(blob):
        return True, "React internals (react-dom / dangerouslySetInnerHTML handler)"
    if _REDUX_TOOLKIT_SIGS.search(blob):
        return True, "Redux Toolkit internals (createAsyncThunk / action suffixes)"
    if _AXIOS_SIGS.search(blob):
        return True, "Axios HTTP client internals"
    if _NEXT_INTERNAL_SIGS.search(blob):
        return True, "Next.js framework chunk"
    if _VUE_INTERNAL_SIGS.search(blob):
        return True, "Vue runtime internals"
    return False, ""


def _is_test_or_public_url(match: str) -> tuple[bool, str]:
    if not match:
        return False, ""
    m = match.strip().strip('"').strip("'").strip("`")
    if _TEST_URL_FIXTURES.match(m):
        return True, "URL parser test fixture (core-js polyfill)"
    if _W3_NAMESPACES.match(m):
        return True, "W3C namespace URI (required by SVG/MathML spec)"
    if _PUBLIC_CDN_HOSTS.match(m):
        return True, "well-known third-party domain (docs / analytics / CDN)"
    if _IMAGE_CDN_HOSTS.match(m):
        return True, "image CDN -- static asset URL"
    return False, ""


def _looks_like_real(finding) -> tuple[bool, str]:
    """Strong positive signals -- escalate to real even if context is noisy."""
    if finding.category in _REAL_CATEGORIES:
        return True, f"semantic detector hit: {finding.category}"
    if _REAL_NAME_KEYWORDS.search(finding.name or ""):
        return True, f"name pattern: '{finding.name}' is high-signal"
    if _REAL_PATH_KEYWORDS.search(finding.match or ""):
        return True, "path includes high-risk keyword (impersonate / switch-role / backup)"
    blob = (finding.snippet or "") + " " + (finding.context or "")
    if _STORAGE_TOKEN_PATTERNS.search(blob):
        return True, "auth token stored in localStorage -- amplifies XSS impact"
    return False, ""


def triage_one(finding) -> tuple[str, str]:
    """
    Return (verdict, reason) for a single finding.

    Order matters: we check strong real signals first so they aren't
    accidentally masked by framework-context detection (e.g. an admin
    path that happens to be referenced inside a Next.js routing chunk
    should stay 'real', not get downgraded to 'fp').
    """
    # Strong positives first -- never downgrade these
    is_real, reason = _looks_like_real(finding)
    if is_real:
        return "real", reason

    # Public/test URL patterns -- these are unambiguous FPs regardless of
    # context (they're literally test fixtures or third-party constants).
    is_pub, reason = _is_test_or_public_url(finding.match or "")
    if is_pub:
        return "fp", reason

    # Redux action suffix paths
    if _REDUX_ACTION_SUFFIX.match(finding.match or ""):
        return "fp", "Redux action suffix (createAsyncThunk action type)"

    # Next.js build paths
    if _NEXT_BUILD_PATH.match(finding.match or ""):
        return "fp", "Next.js build-time path (framework internal)"

    # Axios localhost fallback (very specific pattern)
    if _AXIOS_LOCALHOST_FALLBACK.search((finding.snippet or "") + (finding.context or "")):
        return "fp", "Axios SSR fallback base URL -- intentional library code"

    # Framework chunks -- only downgrade sinks and AST noise here, not endpoints
    # or secrets, because a real /admin path inside a Next chunk is still real.
    cat = (finding.category or "").lower()
    if cat in ("sinks", "ast:sink", "debug") or cat.startswith("ast:"):
        is_fw, reason = _is_framework_chunk(finding)
        if is_fw:
            return "fp", reason

    # AST-extracted noise patterns
    sink_noise = {"tostring", "valueof", "hasownproperty", "__proto__",
                  "constructor", "isprototypeof", "tolocalestring",
                  "propertyisenumerable", "settimeout", "setinterval"}
    if (finding.match or "").strip().lower() in sink_noise:
        is_fw, reason = _is_framework_chunk(finding)
        if is_fw:
            return "fp", f"{finding.match}() in {reason}"
        # Even outside framework chunks, these are very low-signal AST patterns
        if cat.startswith("ast:sink"):
            return "fp", f"generic '{finding.match}' AST extraction -- no taint signal"

    # Default: needs human review
    return "verify", ""


def triage_findings(findings: list) -> dict:
    """
    Walk all findings, set `.verdict` and `.verdict_reason` on each.

    Returns a summary dict: {"real": N, "verify": N, "fp": N}.
    """
    counts = {"real": 0, "verify": 0, "fp": 0}
    for f in findings:
        # Don't override an operator-set verdict if one was loaded from a
        # session file.
        if f.verdict in ("real", "verify", "fp"):
            counts[f.verdict] = counts.get(f.verdict, 0) + 1
            continue
        verdict, reason = triage_one(f)
        f.verdict = verdict
        f.verdict_reason = reason
        counts[verdict] = counts.get(verdict, 0) + 1
    return counts
