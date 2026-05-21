# Changelog

## 2.0.0 -- Semantic analysis release

This release moves kx from "pattern matcher" to "semantic reader". The
tool no longer just searches for known dangerous strings; it builds a
per-file semantic model and reasons about bug *classes*.

### Added

#### Semantic-detector pipeline (the big one)
For every JS file analysed, kx now:

1. Parses the AST and builds a structural model:
   - Form schemas (zod, yup, joi, vee-validate, svelte-forms-lib, others)
   - Form hooks (react-hook-form, vee-validate, custom)
   - Mutation/query hooks (react-query, swr, custom)
   - Session refs (next-auth, custom)
   - Network calls (fetch, axios, custom HTTP clients)
   - Prop destructuring, sinks, JSX renders

2. Identifies imports by **usage shape**, not name -- so it works on
   production-minified bundles where every import is a 1-2 char alias.

3. Runs six structural bug-class detectors:
   - **Client-side-only validation** -- server-bypass-able auth checks
   - **Sensitive ID in mutation body** -- IDOR via client-supplied IDs
   - **User-controlled URL submitted to backend** -- SSRF candidates
   - **Permission/role field set by client** -- privilege escalation
   - **Inter-procedural taint to sinks** -- eval/innerHTML reached by URL input
   - **Raw network call with sensitive fields** -- same as above for vanilla
     fetch/axios without a form/mutation hook

4. Runs five inline AST-walking detectors:
   - **postMessage handler without origin validation** -- distinguishes
     "no origin check" (HIGH) from "reads but never compares" (MEDIUM);
     correctly suppresses handlers with real equality/inclusion checks
   - **Auth token in localStorage/sessionStorage** -- XSS-equivalent storage
     of token-named keys
   - **JWT decoded client-side and used for authorization** -- `jwtDecode()`
     output gating on `.role` / `.isAdmin` / `.permissions` (HIGH; client
     can rewrite payloads)
   - **Hardcoded role/permission string literals** -- informational LOW;
     intentionally suppressed inside Zod `.enum()` definitions
   - **WebSocket without auth in URL or protocol** -- CSWSH primitive;
     suppressed when token is in URL or for localhost

#### Inter-procedural taint propagation
New fixed-point taint analyser tracks user input from sources
(`location.*`, `URLSearchParams`, `useParams`, `document.getElementById().value`)
through assignments, destructuring, transformations, and into sinks.

#### Chunk-manifest resolver
Parses Vite, Webpack, Rollup, and Next.js chunk manifests in entry bundles
and force-fetches every lazy-loaded route chunk. Previously, lazy routes
behind a click were invisible to the scanner.

#### Source-map recovery
Fetches every discovered `.js.map`, parses the v3 sourcemap, and emits
each reconstructed original source as a virtual `CrawlResult` with a
synthetic `sourcemap://` URL. Third-party noise (`node_modules`, polyfills,
React/Vue/Angular internals, common UI libs) is filtered by default;
`--sourcemap-noise` keeps them.

Reports render reconstructed-source URLs as `[src] path/to/Original.ts`.

#### LLM verification (opt-in)
`--verify` sends the top semantic findings to Claude with their evidence
chain and a code window. Claude returns a verdict
(`exploitable` / `likely_exploitable` / `needs_testing` / `false_positive`),
a CVSS estimate, a concrete PoC HTTP request, prerequisites, and chaining
notes. Results attach into each finding's evidence list.

Requires `ANTHROPIC_API_KEY`. Hard-capped at 25 findings per run
(`--verify-max`); silently no-ops without a key.

#### Reporter enhancements
- New evidence panels printed for semantic high/critical findings
- Markdown export grows a dedicated "Semantic findings -- evidence chains"
  section per high/critical
- Synthetic sourcemap URLs render as `[src] path/to/file.ts`
- **Per-file hunter's-notes Markdown** (`--per-file-reports`): one
  `reports/<host>/<filename>.md` per JS file with kind tag, schema summary,
  mutation summary, session refs, tainted variables, and all findings
  inline with evidence chains. Designed so a hunter can triage a file
  without re-reading the bundle.

#### New CLI flags
- `--no-source-maps` -- disable sourcemap recovery
- `--sourcemap-noise` -- include third-party recovered sources
- `--verify` -- enable LLM verification pass
- `--verify-max N` -- cap verifier calls
- `--verify-model NAME` -- pick an Anthropic model
- `--per-file-reports [DIR]` -- write per-file hunter's-notes Markdown

### Fixed

- `bare()` in crawler -- `lstrip("www.")` was stripping any combination of
  `w` and `.` characters, so `bare("wpapp.com")` returned `"pp.com"`. Now
  uses real prefix removal.
- `PERMISSION_FIELD_RE` was missing the case-insensitive flag -- fields like
  `whoCanChange` weren't matching the lowercase `whocanchange` literal.
- `URL_FIELD_RE` matched bare `notification` (no URL suffix) leading to
  parent-container false positives. Now requires both pattern + suffix
  match.
- `ID_FIELD_RE`/`STRICT_ID_FIELD_RE` extended with longer forms
  (`organizationId`, `customerId`, `subscriptionId`, etc.) and aliases.
- Find dedup key in `analyze.js` now includes line -- distinct findings on
  different lines are no longer collapsed.

### Internal

- `Finding` dataclass extended with optional `note` and `evidence` fields
  (legacy-compatible: defaults preserve existing behaviour).
- `classifier.run_ast` distinguishes `semantic:*` from legacy `ast:*`
  findings; semantic ones get a `[SEM]` tag and a confidence boost.
- `score_finding` boosts semantic findings 25 points above legacy regex
  findings of the same severity.
- All semantic findings carry an `evidence: [{kind, line, snippet}]` chain
  that survives through JSON/Markdown export.

---

## 1.0.0 -- Initial release

Original kx. Async crawler, regex + AST static analysis, Playwright
runtime capture, SQLite diff store, Burp + hunt journal integrations.
