#!/usr/bin/env node
/**
 * kx AST Worker
 * Accepts JS source on stdin, emits JSON findings on stdout.
 * Uses acorn for parsing + custom walkers.
 *
 * Usage: node analyze.js < target.js
 */

const acorn = require("acorn");
const walk = require("acorn-walk");

// Semantic-analysis pipeline (additive -- runs after legacy detectors)
const { buildModel } = require("./semantic_model.js");
const { runDetectors } = require("./detectors.js");
const { propagate: propagateTaint } = require("./taint.js");

const source = (() => {
  const chunks = [];
  process.stdin.resume();
  process.stdin.on("data", d => chunks.push(d));
  return new Promise(r => process.stdin.on("end", () => r(chunks.join(""))));
})();

// ─── helpers ────────────────────────────────────────────────────────────────

function loc(node) {
  return node?.loc?.start?.line ?? 0;
}

function safeString(node) {
  if (!node) return null;
  if (node.type === "Literal" && typeof node.value === "string") return node.value;
  if (node.type === "TemplateLiteral") {
    // Reconstruct if all quasis are static
    const parts = node.quasis.map(q => q.value.cooked || "");
    return parts.join("..."); // placeholder for dynamic parts
  }
  return null;
}

// Constant folding: resolve BinaryExpression "a" + "b" → "ab"
function foldString(node) {
  if (!node) return null;
  if (node.type === "Literal") return typeof node.value === "string" ? node.value : null;
  if (node.type === "TemplateLiteral") return safeString(node);
  if (node.type === "BinaryExpression" && node.operator === "+") {
    const l = foldString(node.left);
    const r = foldString(node.right);
    if (l !== null && r !== null) return l + r;
    if (l !== null) return l;
    if (r !== null) return r;
  }
  return null;
}

// ─── detectors ──────────────────────────────────────────────────────────────

const findings = [];

function emit(category, name, severity, value, line, extra = {}) {
  findings.push({ category, name, severity, value, line, ...extra });
}

// Dangerous sinks
const SINKS = {
  "eval":                 { sev: "high",   cat: "sink" },
  "Function":             { sev: "high",   cat: "sink" },
  "setTimeout":           { sev: "medium", cat: "sink" },
  "setInterval":          { sev: "medium", cat: "sink" },
};

const SINK_MEMBERS = {
  "innerHTML":            { sev: "medium", cat: "sink" },
  "outerHTML":            { sev: "medium", cat: "sink" },
  "insertAdjacentHTML":   { sev: "medium", cat: "sink" },
  "document.write":       { sev: "medium", cat: "sink" },
};

// User-input sources
const INPUT_SOURCES = new Set([
  "location", "search", "hash", "href", "pathname",
  "query", "params", "body", "req", "request", "input",
  "URLSearchParams", "FormData",
]);

function isUserInput(node) {
  if (!node) return false;
  const s = safeString(node);
  if (s) return false; // static string is not user input
  if (node.type === "MemberExpression") {
    const obj = node.object?.name || node.object?.object?.name || "";
    const prop = node.property?.name || "";
    if (INPUT_SOURCES.has(obj) || INPUT_SOURCES.has(prop)) return true;
  }
  if (node.type === "Identifier" && INPUT_SOURCES.has(node.name)) return true;
  return false;
}

// ─── AST walks ──────────────────────────────────────────────────────────────

async function analyse(code) {
  let ast;
  try {
    ast = acorn.parse(code, {
      ecmaVersion: "latest",
      sourceType: "module",
      locations: true,
      allowHashBang: true,
      allowAwaitOutsideFunction: true,
      allowImportExportEverywhere: true,
    });
  } catch (e) {
    // Try script mode fallback
    try {
      ast = acorn.parse(code, {
        ecmaVersion: "latest",
        sourceType: "script",
        locations: true,
        allowHashBang: true,
      });
    } catch (e2) {
      process.stderr.write(`AST parse error: ${e2.message}\n`);
      return;
    }
  }

  // 1. Endpoint / URL string extraction with concat reconstruction
  walk.simple(ast, {
    Literal(node) {
      if (typeof node.value !== "string") return;
      const v = node.value;
      if (/^\/[a-zA-Z0-9/_\-]{2,}/.test(v) && v.length > 3) {
        emit("endpoint", "String Literal Path", "info", v, loc(node));
      }
      if (/^(https?|wss?):\/\//.test(v)) {
        emit("endpoint", "Hardcoded URL", "medium", v, loc(node));
      }
    },
    BinaryExpression(node) {
      if (node.operator !== "+") return;
      const folded = foldString(node);
      if (folded && /^(\/[a-zA-Z]|https?:|wss?:)/.test(folded)) {
        emit("endpoint", "Concatenated URL/Path", "medium", folded, loc(node), {
          note: "reconstructed via constant folding"
        });
      }
    },
    TemplateLiteral(node) {
      const v = safeString(node);
      if (v && (/^\/[a-zA-Z0-9/_\-]{2,}/.test(v) || /^https?:/.test(v))) {
        emit("endpoint", "Template Literal Path", "medium", v, loc(node));
      }
    },
  });

  // 2. Sink detection with user-input taint check
  walk.simple(ast, {
    CallExpression(node) {
      // eval(x), setTimeout("str"), new Function(...)
      const callee = node.callee;
      const name =
        callee.type === "Identifier" ? callee.name :
        callee.type === "MemberExpression" ? callee.property?.name : null;

      if (name && SINKS[name]) {
        const arg0 = node.arguments?.[0];
        const tainted = arg0 && isUserInput(arg0);
        const sev = tainted ? "high" : SINKS[name].sev;
        emit("sink", `${name}() call`, sev, name, loc(node), {
          tainted,
          note: tainted ? "argument may be user-controlled" : undefined,
        });
      }
    },
    AssignmentExpression(node) {
      // x.innerHTML = y
      if (node.left?.type !== "MemberExpression") return;
      const prop = node.left.property?.name;
      if (!prop || !SINK_MEMBERS[prop]) return;
      const tainted = isUserInput(node.right);
      const sev = tainted ? "high" : SINK_MEMBERS[prop].sev;
      emit("sink", `${prop} assignment`, sev, prop, loc(node), { tainted });
    },
  });

  // 3. Dynamic import / lazy chunk discovery
  walk.simple(ast, {
    ImportExpression(node) {
      const src = foldString(node.source) || safeString(node.source);
      if (src) emit("chunk", "Dynamic import()", "info", src, loc(node));
    },
    CallExpression(node) {
      // require("...")
      if (
        node.callee?.name === "require" &&
        node.arguments?.[0]?.type === "Literal"
      ) {
        emit("chunk", "require() call", "info", node.arguments[0].value, loc(node));
      }
      // __webpack_require__(id)
      if (node.callee?.name === "__webpack_require__") {
        const id = node.arguments?.[0]?.value;
        if (id !== undefined) emit("chunk", "webpack chunk id", "info", String(id), loc(node));
      }
    },
  });

  // 4. Prototype pollution patterns
  walk.simple(ast, {
    CallExpression(node) {
      const callee = node.callee;
      // Object.assign(target, source)
      if (
        callee?.type === "MemberExpression" &&
        callee.object?.name === "Object" &&
        callee.property?.name === "assign"
      ) {
        const src = node.arguments?.[1];
        if (src && isUserInput(src)) {
          emit("sink", "Object.assign() prototype pollution risk", "high", "Object.assign", loc(node), {
            tainted: true,
          });
        }
      }
    },
  });

  // 5. Dead code / feature flags (if (false), process.env.NODE_ENV === 'development')
  walk.simple(ast, {
    IfStatement(node) {
      const test = node.test;
      // if (false) or if (0)
      if (test?.type === "Literal" && !test.value) {
        emit("dead_code", "Dead if-block (always false)", "low", "if (false)", loc(node));
        return;
      }
      // if (process.env.NODE_ENV === 'development')
      if (
        test?.type === "BinaryExpression" &&
        test.operator === "===" &&
        foldString(test.right) === "development"
      ) {
        emit("dead_code", "Dev-only code block", "medium", "NODE_ENV===development", loc(node), {
          note: "may contain debug routes or admin endpoints",
        });
      }
    },
  });

  // 6. postMessage without origin validation -- real check
  walk.simple(ast, {
    CallExpression(node) {
      if (
        node.callee?.type === "MemberExpression" &&
        (node.callee.object?.name === "window" || node.callee.object?.type === "ThisExpression") &&
        node.callee.property?.name === "addEventListener"
      ) {
        const evt = node.arguments?.[0];
        if (safeString(evt) !== "message") return;
        const handler = node.arguments?.[1];
        if (!handler) return;
        // Inspect handler body for actual origin validation, not just presence.
        // A real check is: `event.origin === "..."`, `event.origin !== "..."`,
        // `allowedOrigins.includes(event.origin)`, `/regex/.test(event.origin)`.
        // Plain reads (`console.log(event.origin)`) DON'T count.
        let hasOriginCompare = false;
        let mentionsOrigin = false;
        walk.simple(handler, {
          MemberExpression(mn) {
            if (mn.property?.name === "origin") mentionsOrigin = true;
          },
          BinaryExpression(bn) {
            // `event.origin === "..."` / `event.origin !== "..."`
            if (["===","!==","==","!="].includes(bn.operator)) {
              const checkSide = (s) =>
                s?.type === "MemberExpression" && s.property?.name === "origin";
              if (checkSide(bn.left) || checkSide(bn.right)) {
                hasOriginCompare = true;
              }
            }
          },
          CallExpression(cn) {
            // Array#includes, Set#has, regex test
            const m = cn.callee;
            if (m?.type === "MemberExpression" &&
                ["includes","has","indexOf","test","match"].includes(m.property?.name)) {
              // any arg references .origin?
              for (const a of cn.arguments) {
                if (a?.type === "MemberExpression" && a.property?.name === "origin") {
                  hasOriginCompare = true;
                }
              }
              // or the callee's object is a regex or array literal + we see
              // an .origin arg -- handled above.
            }
          },
        });
        const sev = !mentionsOrigin ? "high" : (hasOriginCompare ? null : "medium");
        if (sev === null) return; // legit origin check present
        findings.push({
          category: "semantic:postmessage_no_origin_check",
          name: !mentionsOrigin
            ? "postMessage listener does not read event.origin (no origin check)"
            : "postMessage listener reads event.origin but never compares it",
          severity: sev,
          value: "addEventListener(message)",
          line: loc(node),
          note: !mentionsOrigin
            ? "Handler accepts messages from any origin. An attacker page can postMessage to this window and trigger handler logic. Verify whether the handler performs sensitive actions (auth, data modification)."
            : "Handler reads event.origin but doesn't perform an equality/inclusion check on it. Confirm whether the value is enforced anywhere.",
          evidence: [
            { kind: "addEventListener", line: loc(node), snippet: "window.addEventListener('message', ...)" },
          ],
        });
      }
    },
  });

  // ── New detector: token in localStorage / sessionStorage ──
  //   localStorage.setItem("token", x) / sessionStorage.setItem("jwt", x)
  // Any auth-token-named key written to JS-accessible storage is XSS-equivalent.
  walk.simple(ast, {
    CallExpression(node) {
      const c = node.callee;
      if (c?.type !== "MemberExpression") return;
      const storageObj = c.object?.name;
      const method = c.property?.name;
      if (!["localStorage","sessionStorage"].includes(storageObj)) return;
      if (!["setItem","getItem"].includes(method)) return;
      const keyNode = node.arguments?.[0];
      const key = safeString(keyNode) || "";
      if (!key) return;
      // Match common token/credential key names
      const tokenKeyRe = /(^|[._-])(token|jwt|auth|access[._-]?token|refresh[._-]?token|id[._-]?token|bearer|session|api[._-]?key|secret|credentials?)([._-]|$)/i;
      if (!tokenKeyRe.test(key)) return;
      findings.push({
        category: "semantic:storage_token",
        name: `Auth token in ${storageObj} (XSS-equivalent)`,
        severity: "medium",
        value: `${storageObj}.${method}("${key}")`,
        line: loc(node),
        note: `Token-shaped key "${key}" is stored in ${storageObj}, which is accessible to any JavaScript on the same origin. An XSS bug here exfiltrates the token. Prefer httpOnly+secure cookies for session material.`,
        evidence: [
          { kind: "storage_call", line: loc(node), snippet: `${storageObj}.${method}("${key}")` },
        ],
      });
    },
  });

  // ── New detector: JWT decoded client-side and used for authorization ──
  //   const decoded = jwtDecode(token); if (decoded.role === "admin") ...
  // Trusting JWT contents on the client without verifying signature is a
  // bypass: anyone can rewrite the payload and the client UI accepts it.
  // We look for: (a) a call to a jwt-decode-shaped function, (b) the return
  // being used in a permission/role comparison.
  const jwtVars = new Set();
  walk.simple(ast, {
    VariableDeclarator(node) {
      if (!node.init || node.id?.type !== "Identifier") return;
      // Match calls to anything looking like jwt-decode
      const callee = node.init.type === "CallExpression" ? node.init.callee : null;
      if (!callee) return;
      const name = callee.type === "Identifier" ? callee.name
                 : callee.type === "MemberExpression" ? callee.property?.name : null;
      if (name && /^(jwt[_-]?decode|jwtDecode|decodeJwt|decodeJWT|parseJwt|parseJWT)$/i.test(name)) {
        jwtVars.add(node.id.name);
      }
    },
  });
  if (jwtVars.size) {
    walk.simple(ast, {
      BinaryExpression(node) {
        if (!["===","!==","==","!="].includes(node.operator)) return;
        const check = (side, other) => {
          if (side?.type !== "MemberExpression") return false;
          // Root identifier must be a jwt-decoded variable
          let cur = side;
          while (cur?.type === "MemberExpression") cur = cur.object;
          if (cur?.type !== "Identifier" || !jwtVars.has(cur.name)) return false;
          // The accessed property must be a permission-relevant one
          const prop = side.property?.name;
          if (!prop) return false;
          if (!/^(role|isAdmin|admin|permission|permissions|access|scope|sub|tier|userType)$/i.test(prop)) return false;
          // The other side should be a string literal (role check)
          if (other?.type === "Literal" && typeof other.value === "string") return true;
          return false;
        };
        if (check(node.left, node.right) || check(node.right, node.left)) {
          const idx = check(node.left, node.right) ? node.left : node.right;
          const path = safeString(idx.property) || idx.property?.name || "?";
          findings.push({
            category: "semantic:jwt_client_authz",
            name: "JWT payload used for authorization decision client-side",
            severity: "high",
            value: path,
            line: loc(node),
            note: "Client decodes a JWT (no signature verification possible in the browser) and gates UI / state on the decoded payload. An attacker can rewrite the JWT body to set role='admin' or similar and the client will trust it. Verify the server enforces the same check.",
            evidence: [
              { kind: "jwt_authz_check", line: loc(node),
                snippet: `decoded.${path} ${node.operator} <string literal>` },
            ],
          });
        }
      },
    });
  }

  // ── New detector: hardcoded admin/role string literals ──
  //   if (user.role === "admin") ...
  //   if (permissions.includes("super_admin")) ...
  // These give away the exact strings the server probably accepts.
  // They're not vulnerabilities on their own -- they're INFORMATION leaks
  // useful for crafting privilege-escalation payloads.
  //
  // Skip when the literal lives inside an enum/oneOf/literal *schema*
  // definition -- that's intentional, not a leak. We track ancestors with
  // walk.ancestor to know the enclosing context.
  const seenRoleStrings = new Set();
  walk.ancestor(ast, {
    Literal(node, ancestors) {
      if (typeof node.value !== "string") return;
      const v = node.value;
      // Tight match: short, snake/camel/kebab role-name-shaped strings
      if (!/^(super[._-]?admin|admin|root|owner|moderator|sysadmin|superuser|god[._-]?mode|developer|maintainer|operator|staff)$/i.test(v)) return;
      // Skip if any ancestor CallExpression is a schema-definition call.
      // Schema-defining method names: enum, oneOf, literal, valid, equals,
      // pattern, refine (with a string arg).
      const SCHEMA_METHODS = new Set([
        "enum","oneOf","literal","valid","equals","include","exclude","values",
      ]);
      const inSchema = ancestors.some(a => {
        if (a.type !== "CallExpression") return false;
        const c = a.callee;
        if (c?.type === "MemberExpression" && c.property?.type === "Identifier") {
          return SCHEMA_METHODS.has(c.property.name);
        }
        return false;
      });
      if (inSchema) return;
      if (seenRoleStrings.has(v)) return;
      seenRoleStrings.add(v);
      findings.push({
        category: "semantic:hardcoded_role",
        name: `Hardcoded role/permission string "${v}"`,
        severity: "low",
        value: v,
        line: loc(node),
        note: `Role/permission literal "${v}" appears in client code. The server likely accepts the same value. When testing privilege-relevant fields (role, permissions, isAdmin), try this exact string.`,
        evidence: [
          { kind: "role_literal", line: loc(node), snippet: `"${v}"` },
        ],
      });
    },
  });

  // ── New detector: WebSocket connection without explicit auth ──
  //   new WebSocket("wss://api.target.com/ws")  -- and no token in URL/protocol
  // CSWSH primitive: server auths via cookie, attacker page opens WS,
  // gets credentialed connection.
  walk.simple(ast, {
    NewExpression(node) {
      if (node.callee?.type !== "Identifier" || node.callee.name !== "WebSocket") return;
      const urlNode = node.arguments?.[0];
      const url = safeString(urlNode) || "";
      const protocolNode = node.arguments?.[1];
      // Heuristic: token in URL = "token=", "access_token=", "jwt=", "auth="
      const hasTokenInUrl = /[?&](token|access[_-]?token|jwt|auth|api[_-]?key|key)=/i.test(url);
      const hasProtocol = !!protocolNode;
      if (hasTokenInUrl || hasProtocol) return;
      // Skip ws:// to localhost / development
      if (url && /(localhost|127\.0\.0\.1|0\.0\.0\.0)/.test(url)) return;
      findings.push({
        category: "semantic:websocket_no_auth_in_url",
        name: "WebSocket connection with no explicit auth in URL or protocol",
        severity: "medium",
        value: url || "<dynamic URL>",
        line: loc(node),
        note: "WebSocket opened without an auth token in the URL or sub-protocol parameter. If the server authenticates via cookies, this is vulnerable to cross-site WebSocket hijacking (CSWSH): an attacker page can open a credentialed connection. Verify origin checking on the server.",
        evidence: [
          { kind: "websocket_open", line: loc(node), snippet: `new WebSocket(${url || '<dynamic>'})` },
        ],
      });
    },
  });

  // ── 7. Semantic pipeline (model → detectors) ──
  // Runs independently of legacy detectors; appends findings into the same array.
  // Also produces a per-file summary surfaced via the top-level emitter so the
  // Python side can render hunter-notes Markdown reports.
  let semanticSummary = null;
  try {
    const model = buildModel(ast, code);
    const tainted = propagateTaint(ast);
    const semFindings = runDetectors(model, code, tainted);
    for (const f of semFindings) {
      // Map semantic-detector severities to the existing emit() contract.
      // Critical/high/medium/low are already aligned.
      findings.push({
        category: `semantic:${f.category}`,
        name: f.name,
        severity: f.severity,
        value: String(f.value || "").slice(0, 200),
        line: f.line || 0,
        note: f.note || "",
        evidence: f.evidence || [],
        tainted: f.category === "tainted_sink",
      });
    }
    // Build a small JSON-safe summary of the model. AST node references are
    // intentionally NOT included -- they're huge and circular.
    semanticSummary = {
      sourceLength: code.length,
      schemas: Object.entries(model.schemas).map(([name, s]) => ({
        name,
        line: s.line,
        fieldCount: s.fields.length,
        topFields: s.fields.filter(f => !f.path.includes(".")).map(f => f.path).slice(0, 25),
        refines: (s.refines || []).map(r => ({
          path: r.path, message: r.message, line: r.line,
        })),
      })),
      forms: model.forms.map(f => ({
        line: f.line,
        resolverSchema: f.resolverSchema,
        hookAlias: f.hookAlias,
        destructured: f.destructured.map(d => d.original),
      })),
      mutations: model.mutations.map(m => ({
        varName: m.varName,
        hookCategory: m.hookCategory,
        hookAlias: m.hookAlias,
        line: m.line,
        payloads: m.payloads.map(p => ({
          line: p.line,
          keys: p.keys,
          spreads: p.spreads,
          indirect: p.indirect || null,
          fieldsResolved: p.fieldsResolved.map(fr => ({
            key: fr.key, originType: fr.originType, originName: fr.originName,
          })),
        })),
      })),
      networkCalls: model.networkCalls.map(n => ({
        kind: n.kind,
        line: n.line,
        urlString: n.urlString,
        bodyKeys: n.bodyKeys,
      })),
      sessionRefs: model.sessionRefs,
      sinks: model.sinks.map(s => ({
        kind: s.kind, name: s.name, line: s.line,
      })),
      taintedVars: [...tainted].slice(0, 50),
      propOriginByLocal: model.propOriginByLocal || {},
    };
  } catch (e) {
    process.stderr.write(`Semantic pipeline error: ${e.message}\n${e.stack}\n`);
  }
  // Stash on the analyse() result so the entrypoint can include it.
  return { summary: semanticSummary };
}

// ─── main ────────────────────────────────────────────────────────────────────

source.then(async code => {
  const analyseResult = await analyse(code) || {};
  // Deduplicate by (name, value, line) -- line included so two genuinely distinct
  // findings on different lines (e.g. same field name flagged in two payloads)
  // are not collapsed.
  const seen = new Set();
  const deduped = findings.filter(f => {
    const k = `${f.name}::${String(f.value).slice(0, 80)}::${f.line || 0}`;
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  // Emit a wrapper envelope: {findings, summary}. Old consumers that read
  // the previous bare-array format can still parse it via a fallback
  // (classifier.py supports both).
  process.stdout.write(JSON.stringify({
    findings: deduped,
    summary: analyseResult.summary || null,
  }, null, 2));
}).catch(e => {
  process.stderr.write(`Fatal: ${e.message}\n`);
  process.stdout.write(JSON.stringify({ findings: [], summary: null }));
});
