/**
 * kx -- Semantic Detectors
 *
 * Each detector is a pure function: (model) -> findings[]
 * They read the semantic model produced by semantic_model.js and emit
 * structured findings in the same shape as the legacy AST analyzer.
 *
 * Finding shape:
 *   {
 *     category, name, severity,
 *     value, line,                   // primary location
 *     note,                          // human-readable evidence
 *     evidence: [{kind, line, snippet}, ...]
 *   }
 */

"use strict";

// ─────────────────────────────────────────────────────────────────────────
// Structural evidence helpers
//
// Detectors used to emit raw minified-JS snippets as evidence, e.g.
//   { kind: "spread_transit",
//     snippet: "RL:l,hashKey:s}};t&&ma({merchantID:t,...ce}..." }
//
// Useless to read.  We replace that with structural sentences computed
// from the semantic model.  Example output:
//
//   { kind: "spread_transit",
//     snippet: "ma({merchantID:t, ...ce}) -- 1 explicit key + 1 spread" }
//   { kind: "spread_member",
//     snippet: "spread `ce` ← form values (incl. whoCanChange)" }
//
// The raw blob is still available on the payload object for anyone who
// wants full bytes; we just don't dump it into evidence by default.

function _summarizePayload(payload, mut) {
  // One short, readable line describing what the mutation actually sends.
  const explicit = (payload.keys || []).filter(k => k !== "...");
  const spreads  = payload.spreads || [];
  const callExpr = `${mut.varName}({${[
    ...explicit.map(k => k),
    ...spreads.map(s => `...${s}`),
  ].join(", ")}})`;
  const counts = [];
  if (explicit.length) counts.push(`${explicit.length} explicit key${explicit.length === 1 ? "" : "s"}`);
  if (spreads.length)  counts.push(`${spreads.length} spread${spreads.length === 1 ? "" : "s"}`);
  return callExpr + (counts.length ? " -- " + counts.join(" + ") : "");
}

function _summarizeFieldOrigin(fr) {
  // fr = {key, originType, originName}
  // Render the data-flow sentence: "merchantID ← prop:i.merchantID"
  if (!fr || fr.key === "...") return null;
  let arrow = "?";
  switch (fr.originType) {
    case "prop":              arrow = `prop:${fr.originName}`; break;
    case "prop_or_default":   arrow = `prop:${fr.originName} (with default)`; break;
    case "prop_member_or_default": arrow = `prop member:${fr.originName} (with default)`; break;
    case "local":             arrow = `local:${fr.originName || "?"}`; break;
    case "literal":           arrow = "literal"; break;
    case "session":           arrow = "session"; break;
    case "session_or_default":arrow = "session (with default)"; break;
    case "form":              arrow = `form value:${fr.originName || "?"}`; break;
    case "url":               arrow = `URL param:${fr.originName || "?"}`; break;
    case "unknown":           arrow = "unknown"; break;
    default:                  arrow = fr.originType + (fr.originName ? `:${fr.originName}` : "");
  }
  return `${fr.key} ← ${arrow}`;
}

function _summarizeSpreadMember(payload, spreadName, schemaName) {
  // For privilege-escalation detector: a payload spread `...ce` likely
  // contains a form-values object. We say which spread, and which schema
  // contributes a permission-shaped field.
  return `spread \`${spreadName}\``
       + (schemaName ? ` ← values of form schema "${schemaName}"` : ` ← form values`);
}

// Match the FINAL segment of a dotted path (e.g. `notificationSetting.notificationURL`
// → we test "notificationURL"). Requires the suffix actually contains a URL-ish word.
// Words like "notificationSetting" alone should NOT match.
const URL_FIELD_RE = /(url|uri|endpoint|webhook|callback|redirect|address|hostname|host)$/i;
// And to avoid stamping ANYTHING ending in "host" (e.g. "ghost"), also require
// at least one earlier hint:
const URL_FIELD_CONFIRM_RE = /(url|uri|webhook|callback|notification|redirect|notify|forward|endpoint|ping|hook)/i;

// ── ID-field detection ──────────────────────────────────────────────────────
// A key is "ID-like" only if it ends in a *boundaried* id: exact `id`,
// camelCase `...Id`, ALLCAPS `...ID`, or snake_case `..._id`. The boundary is
// the whole point -- the old `id$/i` matched any lowercase word ending in
// "id" (valid, paid, uuid, android, hybrid, grid, void, kid, candid) and fired
// a stream of bogus IDOR findings. We test case-SENSITIVELY so those lowercase
// words fall through, and keep an explicit excludelist for the ALLCAPS/camel
// collisions the boundary alone can't separate (UUID, GUID, VOID, GRID...).
const ID_SUFFIX_RE = /(^id$|Id$|ID$|_id$)/;
const ID_FALSE_WORDS = new Set([
  "valid", "invalid", "uuid", "guid", "void", "avoid", "ovoid", "paid",
  "unpaid", "overpaid", "android", "hybrid", "grid", "kid", "candid", "rapid",
  "solid", "fluid", "squid", "rigid", "vivid", "lucid", "acid", "humid",
  "timid", "bid", "rid", "lid", "mid", "did", "hid", "aid", "raid", "maid",
  "braid", "afraid", "forbid", "amid", "morbid", "placid",
]);
const ID_ENTITY_RE = /^(merchant|user|account|org|organization|tenant|customer|owner|team|workspace|project|store|shop|business|company|subscription|invoice|order|payment|client|partner|profile|seller|buyer|member|group)/i;

function looksLikeId(key) {
  if (!key || ID_FALSE_WORDS.has(key.toLowerCase())) return false;
  return ID_SUFFIX_RE.test(key);
}
// Entity-scoped IDs (merchantId, userID, account_id) -- the high-confidence
// horizontal-privesc set. Equivalent to the old STRICT_ID_FIELD_RE intent.
function looksLikeEntityId(key) {
  return looksLikeId(key) && ID_ENTITY_RE.test(key);
}

// ── Permission-field detection ──────────────────────────────────────────────
// Anchored word list (case-insensitive) PLUS a curated set of privilege-bearing
// `can<Verb>` flags. The old `^can[A-Z]/i` matched ANY letter after "can"
// because the /i flag makes [A-Z] case-insensitive -- so cancel, canvas,
// candidate, cannot all read as privilege escalation. We list real privilege
// verbs explicitly and match them case-sensitively (camelCase boundary).
const PERMISSION_WORD_RE = /^(role|roles|isadmin|is_admin|permission|permissions|whocanchange|who_can_change|accesslevel|access_level|usertype|user_type|tier|privilege|privileges|capability|capabilities|superuser|is_superuser|issuperuser|superadmin|admin|owner)$/i;
const PERMISSION_CAN_RE  = /^can(Change|Delete|Manage|Edit|Grant|Assign|Approve|Publish|Configure|Override|Impersonate|Administer|Modify|Remove|Invite|Promote|Revoke|Escalate)/;

function looksLikePermission(key) {
  return !!key && (PERMISSION_WORD_RE.test(key) || PERMISSION_CAN_RE.test(key));
}

const SAFE_URL_VALIDATORS = /(new\s+URL\s*\(|isURL|validUrl|whitelist|allowlist|startsWith\(["']https|hostname\s*===\s*["'])/i;

// User-controllable inputs for taint
const USER_INPUT_ROOTS = new Set([
  "location", "URLSearchParams", "FormData",
]);
const USER_INPUT_PROPS = new Set([
  "search", "hash", "href", "pathname", "host", "hostname",
]);

// ─── Detector 1: Client-side-only validation ────────────────────────────────
// For each form (useForm + zodResolver(schema)):
//   For each schema field:
//     Does it appear in ANY mutation payload (explicit key or spread root)?
//   If no → client-only check → potential auth/server-side bypass.

function detectClientOnlyValidation(model, source) {
  const findings = [];
  if (!model.forms.length) return findings;

  for (const form of model.forms) {
    const schema = form.resolverSchema ? model.schemas[form.resolverSchema] : null;
    if (!schema) continue;

    // Build the union of every key transmitted by any mutation in this file.
    const transmittedKeys = new Set();
    const spreadRoots = new Set();      // identifiers being spread (likely the whole form data)
    for (const m of model.mutations) {
      for (const p of m.payloads) {
        for (const k of p.keys) transmittedKeys.add(k);
        for (const s of p.spreads) spreadRoots.add(s);
      }
    }
    // Also count network calls
    for (const nc of model.networkCalls) {
      for (const k of (nc.bodyKeys || [])) transmittedKeys.add(k);
    }

    const formHasSpread = spreadRoots.size > 0;

    // Fields provably stripped before a spread: `const { authCode, ...rest } = values`
    // where `rest` is what gets spread into the payload. Those keys never reach
    // the backend -- the strongest possible client-only-validation signal.
    const omittedViaSpread = new Set();
    for (const root of spreadRoots) {
      const ro = (model.restOmissions || {})[root];
      if (ro) for (const k of ro.omitted) omittedViaSpread.add(k);
    }

    // For each top-level schema field, check whether it survives to a payload.
    // We only check the immediate top-level field name (e.g. "authCode"),
    // because nested fields are usually transmitted via spread.
    const topLevelFields = schema.fields.filter(f => !f.path.includes("."));

    for (const field of topLevelFields) {
      const fname = field.path;

      // Skip obviously cosmetic schema parts
      if (/^(label|value|children)$/i.test(fname)) continue;

      const hasRefine = (schema.refines || []).some(r => r?.path === fname);
      const looksSecurity = /^(auth|otp|pin|code|captcha|token|2fa|mfa|tfa|confirm|reauth).*$|.*(otp|2fa|mfa|pin|password|captcha)$/i.test(fname);

      if (!hasRefine && !looksSecurity) continue;

      // Disposition of this field relative to the outgoing payload:
      //   explicit      -> sent as its own key: server sees it, no bypass.   (skip)
      //   omitted       -> destructured out before a spread: server NEVER sees it. (critical)
      //   spread_likely -> a spread is present and the field isn't omitted:
      //                    probably transmitted, but .refine() still runs only
      //                    client-side -- worth a *medium* "verify server" note.
      //   absent        -> no spread, not an explicit key: payload omits it.  (critical)
      if (transmittedKeys.has(fname)) continue;            // explicit -> not a bypass

      const disposition =
        omittedViaSpread.has(fname) ? "omitted" :
        formHasSpread               ? "spread_likely" :
                                      "absent";

      // spread_likely is the weak case: the value is probably sent, so only
      // surface it when there's an actual .refine() rule the server might skip.
      // A merely security-shaped name here is too noisy to flag.
      if (disposition === "spread_likely" && !hasRefine) continue;

      const refineEvidence = (schema.refines || []).find(r => r?.path === fname);
      const omitFrom = disposition === "omitted"
        ? (Object.entries(model.restOmissions || {})
             .find(([, v]) => v.omitted.has(fname))?.[0] || "rest")
        : null;

      const severity = disposition === "spread_likely" ? "medium" : "critical";

      const verdictText =
        disposition === "omitted"
          ? `field destructured out (\`{ ${fname}, ...${omitFrom} }\`) before the spread -- server never receives it`
          : disposition === "spread_likely"
            ? "field likely transmitted via spread, but the .refine() rule runs only client-side"
            : "field NOT in payload -- server never sees it";

      const note =
        disposition === "omitted"
          ? `Field "${fname}" is validated client-side${hasRefine ? " via .refine()" : ""} but is explicitly destructured out (\`const { ${fname}, ...${omitFrom} } = ...\`) before the payload is spread to the backend. The server never receives it, so the client check is the *only* gate -- skip the UI and call the endpoint directly.`
          : disposition === "spread_likely"
            ? `Field "${fname}" is enforced via .refine()${refineEvidence ? ` (line ${refineEvidence.line}): "${refineEvidence.message || "<no message>"}"` : ""}. The value is likely transmitted via a spread payload, but the refine() constraint runs only in the browser -- verify the server re-enforces it.`
            : refineEvidence
              ? `Field "${fname}" enforced only via .refine() (line ${refineEvidence.line}): "${refineEvidence.message || "<no message>"}" -- the mutation payload omits it entirely, so the server never sees it.`
              : `Sensitive-looking field "${fname}" is in the schema but never appears in any mutation payload.`;

      findings.push({
        category: "auth_bypass",
        name: "Client-side-only validation (likely bypass)",
        severity,
        value: fname,
        line: field.line,
        note,
        evidence: [
          { kind: "schema_field", line: field.line, snippet: `${fname}: <validator>` },
          refineEvidence && {
            kind: "refine_rule", line: refineEvidence.line,
            snippet: `.refine() on ${fname}: "${refineEvidence.message || "<no message>"}"`,
          },
          omitFrom && {
            kind: "destructure_omit", line: field.line,
            snippet: `const { ${fname}, ...${omitFrom} } = <form values> -- ${fname} stripped before spread`,
          },
          { kind: "transmitted_keys",
            line: model.mutations[0]?.payloads[0]?.line || 0,
            snippet: `payload keys: {${[...transmittedKeys].join(", ") || "(none)"}}`
                   + (spreadRoots.size ? `, spreads: {...${[...spreadRoots].join(", ...")}}` : "") },
          { kind: "verdict", line: field.line, snippet: verdictText },
        ].filter(Boolean),
      });
    }
  }
  return findings;
}

// ─── Detector 2: Sensitive ID sourced from props/state, not session ─────────
// For each mutation payload: find keys matching ID_FIELD_RE whose origin is
// "prop" or "prop_member" or "user_input", and whose origin is NOT a session
// variable. Emits IDOR / horizontal privilege escalation candidate.

function detectIdInMutation(model, source) {
  const findings = [];
  if (!model.mutations.length) return findings;

  const sessionVarNames = new Set(model.sessionRefs.map(s => s.varName));

  for (const mut of model.mutations) {
    for (const payload of mut.payloads) {
      for (const f of payload.fieldsResolved) {
        if (f.key === "...") continue;
        // Strict match first -- "merchantID", "userId", etc.
        const isStrict = looksLikeEntityId(f.key);
        // Loose match -- any boundaried id ("orderId", "fooId")
        const isLoose = !isStrict && looksLikeId(f.key);
        if (!isStrict && !isLoose) continue;

        // Skip if value originates from a session var
        const fromSession = (f.originType && f.originType.startsWith("session"))
                         || (f.originName && [...sessionVarNames].some(
              s => f.originName === s || f.originName?.startsWith(s + ".")
            ));
        if (fromSession) continue;

        // Accept any origin that traces back to props or user input.
        // localOrigins propagates these through one-hop locals, so the
        // type string may be e.g. "prop_member_or_default".
        const fromProp = f.originType && /^prop/.test(f.originType);
        const fromUserInput = f.originType && /^user_input/.test(f.originType);

        if (!fromProp && !fromUserInput) continue;

        findings.push({
          category: "idor",
          name: "Sensitive ID in mutation body, sourced from client",
          severity: isStrict ? "high" : "medium",
          value: f.key,
          line: payload.line,
          note: `Key "${f.key}" in mutation "${mut.varName}" comes from ${f.originType === "user_input" ? "URL / user input" : "component props"} (${f.originName || "?"}). If the server trusts this value rather than deriving it from the session token, horizontal privilege escalation is possible.`,
          evidence: [
            { kind: "mutation_call",  line: payload.line,
              snippet: _summarizePayload(payload, mut) },
            { kind: "tainted_field",  line: payload.line,
              snippet: _summarizeFieldOrigin(f) },
          ],
        });
      }
    }
  }
  return findings;
}

// ─── Detector 3: User-controlled URL submitted to backend ───────────────────
// Find form-schema fields matching URL_FIELD_RE that flow into a mutation
// payload. Bonus: lower confidence if a URL validator is in scope nearby.

function detectUserControlledUrl(model, source) {
  const findings = [];
  if (!model.forms.length) return findings;

  for (const form of model.forms) {
    const schema = form.resolverSchema ? model.schemas[form.resolverSchema] : null;
    if (!schema) continue;

    const urlFields = schema.fields.filter(f => {
      const last = f.path.split(".").pop();
      return URL_FIELD_RE.test(last) && URL_FIELD_CONFIRM_RE.test(last);
    });
    if (!urlFields.length) continue;

    // Does *any* mutation appear to receive these fields (via spread or explicit)?
    const transmittedKeys = new Set();
    let hasSpread = false;
    for (const m of model.mutations) {
      for (const p of m.payloads) {
        for (const k of p.keys) transmittedKeys.add(k);
        if (p.spreads.length) hasSpread = true;
      }
    }
    for (const nc of model.networkCalls) {
      for (const k of (nc.bodyKeys || [])) transmittedKeys.add(k);
    }

    // Cheap source-scan for evidence of validation around the URL field
    const validationLikely = SAFE_URL_VALIDATORS.test(source);

    for (const f of urlFields) {
      const lastName = f.path.split(".").pop();
      const reachesBackend = hasSpread || transmittedKeys.has(lastName);
      if (!reachesBackend) continue;

      // Find the specific mutation+payload this field reaches
      let reachingMut = null;
      let reachingPayload = null;
      outer: for (const mut of model.mutations) {
        for (const p of mut.payloads) {
          if (transmittedKeys.has(lastName) || p.spreads.length) {
            reachingMut = mut;
            reachingPayload = p;
            break outer;
          }
        }
      }

      findings.push({
        category: "ssrf",
        name: "User-controlled URL submitted to backend (SSRF candidate)",
        severity: validationLikely ? "medium" : "high",
        value: f.path,
        line: f.line,
        note: `Form schema field "${f.path}" looks like a user-supplied URL (webhook/notification/callback). It flows to the backend ${hasSpread ? "via spread payload" : "via explicit mutation key"}. ${validationLikely ? "Some URL validation appears present in this file -- verify it actually constrains the host." : "No URL validation detected -- test with internal IPs, cloud metadata endpoints, and localhost."}`,
        evidence: [
          { kind: "schema_field", line: f.line, snippet: `${f.path}: <user-supplied URL>` },
          { kind: "mutation_call",
            line: reachingPayload?.line || 0,
            snippet: reachingMut && reachingPayload
              ? _summarizePayload(reachingPayload, reachingMut)
              : (hasSpread ? "form spread into mutation payload"
                           : `key "${lastName}" sent in mutation`) },
          { kind: "transit",
            line: reachingPayload?.line || 0,
            snippet: hasSpread
              ? `field reaches backend via spread (no host validation found)`
              : `field reaches backend as explicit key "${lastName}"` },
        ],
      });
    }
  }
  return findings;
}

// ─── Detector 4: Permission/role field controlled by client ─────────────────
// For each mutation payload: keys matching PERMISSION_FIELD_RE are red flags.
// The server should derive permissions from the session, not accept them.

function detectClientControlledPermission(model, source) {
  const findings = [];
  if (!model.mutations.length) return findings;

  for (const mut of model.mutations) {
    for (const payload of mut.payloads) {
      // Combine explicit keys with the recursive set of keys in spread sources.
      const explicitKeys = payload.keys || [];

      // We also want to catch nested permission fields visible in the schema
      // if the same form is being submitted via this mutation. We approximate
      // by scanning the WHOLE source for permission-named identifiers near
      // the form schema. That's too noisy → only do it for explicit keys here.

      for (const key of explicitKeys) {
        if (!looksLikePermission(key)) continue;
        // Find the resolved-field entry so we can describe its origin
        const fr = (payload.fieldsResolved || []).find(x => x.key === key);
        findings.push({
          category: "privilege_escalation",
          name: "Permission/role field set by client in mutation",
          severity: "high",
          value: key,
          line: payload.line,
          note: `Mutation "${mut.varName}" payload contains "${key}", a permission-like field. If the server respects this value, the client can elevate its own privileges. Test by altering this field directly.`,
          evidence: [
            { kind: "mutation_call",   line: payload.line,
              snippet: _summarizePayload(payload, mut) },
            { kind: "controlled_field", line: payload.line,
              snippet: fr ? _summarizeFieldOrigin(fr)
                          : `${key} ← client-controlled` },
          ],
        });
      }

      // Also walk schema fields if this mutation looks linked to a form.
      // (Spread case -- server probably receives the whole form payload.)
      if (payload.spreads.length) {
        // A permission field destructured out before the spread (`const
        // { role, ...rest } = values; mut({...rest})`) is NOT attacker-
        // controllable through this payload -- de-escalate by skipping it.
        const omittedHere = new Set();
        for (const root of payload.spreads) {
          const ro = (model.restOmissions || {})[root];
          if (ro) for (const k of ro.omitted) omittedHere.add(k);
        }
        for (const form of model.forms) {
          const schema = form.resolverSchema ? model.schemas[form.resolverSchema] : null;
          if (!schema) continue;
          // Pick the spread variable name (usually `...formValues` or alias)
          const spreadName = payload.spreads[0];
          for (const f of schema.fields) {
            const last = f.path.split(".").pop();
            if (!looksLikePermission(last)) continue;
            if (omittedHere.has(last) || omittedHere.has(f.path)) continue;
            findings.push({
              category: "privilege_escalation",
              name: "Permission/role field in form schema reaches backend via spread",
              severity: "high",
              value: f.path,
              line: f.line,
              note: `Schema field "${f.path}" is a permission-like field. The form is spread into mutation "${mut.varName}" -- the server receives this value from the client. Test for privilege escalation.`,
              evidence: [
                { kind: "schema_field",  line: f.line,
                  snippet: `${f.path} (permission-shaped)` },
                { kind: "mutation_call", line: payload.line,
                  snippet: _summarizePayload(payload, mut) },
                { kind: "spread_member", line: payload.line,
                  snippet: _summarizeSpreadMember(payload, spreadName, form.resolverSchema) },
              ],
            });
          }
        }
      }
    }
  }

  return findings;
}

// ─── Detector 5: Inter-procedural taint to sinks ─────────────────────────────
// Build a def-use graph (simple): variable X is tainted if assigned from
// user input or from another tainted variable. Then check sinks against the
// taint set.
// Implementation lives in the AST worker because it needs the full AST.
// Here we just consume the model.sinks list and the AST-level taint markings.

function detectInterproceduralTaint(model, source, taintedVars) {
  const findings = [];
  for (const s of model.sinks) {
    if (!s.argNode) continue;
    // Find any identifier in the arg expression that is in taintedVars
    const idsInArg = collectIdentifierNames(s.argNode);
    const taintedHits = [...idsInArg].filter(id => taintedVars.has(id));
    if (!taintedHits.length) continue;
    findings.push({
      category: "tainted_sink",
      name: `${s.name} reached by user-controlled value (inter-procedural)`,
      severity: "critical",
      value: s.name,
      line: s.line,
      note: `Variable(s) [${taintedHits.join(", ")}] reach ${s.name} via assignment chain originating in user input.`,
      evidence: [
        { kind: "sink", line: s.line, snippet: s.argSnippet },
        { kind: "tainted_vars", line: s.line,
          snippet: `tainted: ${taintedHits.join(", ")}` },
      ],
    });
  }
  return findings;
}

function collectIdentifierNames(node, out = new Set()) {
  if (!node || typeof node !== "object") return out;
  if (node.type === "Identifier") { out.add(node.name); return out; }
  for (const k of Object.keys(node)) {
    if (k === "loc" || k === "start" || k === "end" || k === "range") continue;
    const v = node[k];
    if (Array.isArray(v)) v.forEach(c => collectIdentifierNames(c, out));
    else if (v && typeof v === "object" && v.type) collectIdentifierNames(v, out);
  }
  return out;
}

// ─── Detector 6: Raw network call with sensitive client-supplied fields ─────
// Fires on fetch()/axios.*() that send a body containing:
//   - ID-like keys whose values come from URL params or tainted variables
//   - URL/webhook-like keys (SSRF candidates)
//   - permission-like keys (privilege escalation)
// This handles vanilla SPAs and any code without a form/mutation hook.
// Works on the model.networkCalls list which already carries bodyKeys.

function detectRawNetworkCalls(model, source, taintedVars) {
  const findings = [];
  if (!model.networkCalls.length) return findings;

  for (const nc of model.networkCalls) {
    const keys = nc.bodyKeys || [];
    if (!keys.length) continue;

    for (const key of keys) {
      const last = key.split(".").pop();

      // (a) URL-like body field → SSRF candidate
      if (URL_FIELD_RE.test(last) && URL_FIELD_CONFIRM_RE.test(last)) {
        findings.push({
          category: "ssrf",
          name: "User-controlled URL in raw network-call body (SSRF candidate)",
          severity: "high",
          value: key,
          line: nc.line,
          note: `Network call ${nc.kind} → ${nc.urlString || "<dynamic URL>"} sends a body containing "${key}". Test with internal IPs, cloud metadata endpoints, and localhost.`,
          evidence: [
            { kind: "network_call", line: nc.line,
              snippet: `${nc.kind}(${nc.urlString || "?"}, body keys=[${keys.join(",")}])` },
          ],
        });
        continue;
      }

      // (b) Permission/role field
      if (looksLikePermission(last)) {
        findings.push({
          category: "privilege_escalation",
          name: "Permission/role field in raw network-call body",
          severity: "high",
          value: key,
          line: nc.line,
          note: `Network call ${nc.kind} → ${nc.urlString || "<dynamic URL>"} sends a body containing "${key}". If server respects this value, the client can elevate its own privileges.`,
          evidence: [
            { kind: "network_call", line: nc.line,
              snippet: `${nc.kind}(${nc.urlString || "?"}, body keys=[${keys.join(",")}])` },
          ],
        });
        continue;
      }

      // (c) ID-like field -- only emit if the value is tainted (else it might
      // legitimately come from app state). For raw calls we don't have field
      // origin metadata, so we check whether ANY tainted variable's name
      // matches the body key.
      if (looksLikeEntityId(last) && taintedVars && taintedVars.has(last)) {
        findings.push({
          category: "idor",
          name: "Tainted ID in raw network-call body",
          severity: "high",
          value: key,
          line: nc.line,
          note: `Network call ${nc.kind} → ${nc.urlString || "<dynamic URL>"} sends "${key}" sourced from URL/user input. If the server trusts this value rather than the session, horizontal privilege escalation is possible.`,
          evidence: [
            { kind: "network_call", line: nc.line,
              snippet: `${nc.kind}(${nc.urlString || "?"}, body keys=[${keys.join(",")}])` },
            { kind: "tainted_origin", line: nc.line,
              snippet: `"${last}" is in the tainted-variable set` },
          ],
        });
      }
    }
  }
  return findings;
}

// ─── Master runner ─────────────────────────────────────────────────────────

function runDetectors(model, source, taintedVars) {
  const all = [
    ...detectClientOnlyValidation(model, source),
    ...detectIdInMutation(model, source),
    ...detectUserControlledUrl(model, source),
    ...detectClientControlledPermission(model, source),
    ...detectInterproceduralTaint(model, source, taintedVars || new Set()),
    ...detectRawNetworkCalls(model, source, taintedVars || new Set()),
  ];
  // Merge findings of the same category+value at the SAME location.
  // We use category + full value path + line so distinct instances of the
  // same field name (e.g. four `whoCanChange` fields under different parents)
  // stay separate. Two detectors landing on the EXACT same path & line
  // (e.g. schema-detector + raw-network-detector both flagging webhookUrl
  // at the same line) merge into one finding with combined evidence.
  const severityRank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  const merged = new Map();
  for (const f of all) {
    const key = `${f.category}::${String(f.value)}::${f.line || 0}`;
    const existing = merged.get(key);
    if (!existing) {
      merged.set(key, f);
      continue;
    }
    if ((severityRank[f.severity] || 0) > (severityRank[existing.severity] || 0)) {
      merged.set(key, {
        ...f,
        evidence: [...(f.evidence || []), ...(existing.evidence || [])],
      });
    } else {
      existing.evidence = [...(existing.evidence || []), ...(f.evidence || [])];
    }
  }
  return [...merged.values()];
}

module.exports = {
  runDetectors,
  detectClientOnlyValidation,
  detectIdInMutation,
  detectUserControlledUrl,
  detectClientControlledPermission,
  detectInterproceduralTaint,
  detectRawNetworkCalls,
  // exported for unit tests
  _matchers: { looksLikeId, looksLikeEntityId, looksLikePermission },
};
