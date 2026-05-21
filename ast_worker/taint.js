/**
 * kx -- Inter-procedural taint analyser
 *
 * Builds a taint set: every variable provably assigned (directly or
 * transitively) from a user-input source.
 *
 * Sources of taint:
 *   - location.search / .hash / .href / .pathname
 *   - URLSearchParams / FormData usage
 *   - useParams(), useSearchParams() return values
 *   - props of the outermost component (configurable -- off by default
 *     because that's a different finding class)
 *
 * Propagation rules:
 *   - x = TAINTED         → x is tainted
 *   - x = f(TAINTED, ...) → x is tainted (transparent functions)
 *   - x = TAINTED.foo     → x is tainted
 *   - x = a + b, where a or b tainted → x is tainted
 *   - destructured: const {a,b} = TAINTED → a,b tainted
 *
 * NOT propagated:
 *   - x = TAINTED === "..." (booleans break the chain -- usually)
 *   - x = isAdmin(TAINTED)   (no info; conservative: stay tainted to be safe)
 *
 * Output: Set<string> of tainted variable names in the file's flat scope.
 * (We don't model nested scopes precisely -- minified code shadowing means
 * we accept some false positives. Better recall than precision here.)
 */

"use strict";

const walk = require("acorn-walk");

const USER_INPUT_ROOTS = new Set(["location", "URLSearchParams", "FormData"]);
const USER_INPUT_PROPS = new Set([
  "search", "hash", "href", "pathname", "host", "hostname",
]);
const USER_INPUT_CALLS = new Set([
  "useParams", "useSearchParams",
]);

function isUserInputExpression(node) {
  if (!node) return false;
  // location.search, location.hash, etc.
  if (node.type === "MemberExpression") {
    const obj = node.object;
    if (obj?.type === "Identifier" && USER_INPUT_ROOTS.has(obj.name)) return true;
    if (obj?.type === "Identifier" && obj.name === "window") {
      // window.location.X
      if (node.property?.name === "location") return true;
    }
    // window.location.search etc.
    if (obj?.type === "MemberExpression" &&
        obj.object?.name === "window" &&
        obj.property?.name === "location" &&
        USER_INPUT_PROPS.has(node.property?.name)) return true;
    // location.X
    if (obj?.type === "Identifier" && obj.name === "location" &&
        USER_INPUT_PROPS.has(node.property?.name)) return true;
  }
  // new URLSearchParams(X) / new FormData(X)
  if (node.type === "NewExpression" &&
      node.callee?.type === "Identifier" &&
      USER_INPUT_ROOTS.has(node.callee.name)) return true;
  // useParams() / useSearchParams()
  if (node.type === "CallExpression" &&
      node.callee?.type === "Identifier" &&
      USER_INPUT_CALLS.has(node.callee.name)) return true;
  // ChainExpression: a?.b -- unwrap
  if (node.type === "ChainExpression") return isUserInputExpression(node.expression);
  // CallExpression on a user-input member: location.hash.slice(1),
  //   params.get("foo"), new URLSearchParams(...).get(...), etc.
  // The callee is a MemberExpression rooted at a user-input source.
  if (node.type === "CallExpression" && node.callee?.type === "MemberExpression") {
    // Recursively check whether the callee's object is user-input
    if (isUserInputExpression(node.callee.object)) return true;
    // Or -- root identifier of the callee chain is `location` or `window`
    let cur = node.callee.object;
    while (cur && cur.type === "MemberExpression") cur = cur.object;
    if (cur?.type === "Identifier" && USER_INPUT_ROOTS.has(cur.name)) return true;
  }
  // DOM-derived input: document.getElementById(...).value, .files, .innerText, .innerHTML
  // Reading from any DOM element is effectively user-controlled.
  if (node.type === "MemberExpression" &&
      node.object?.type === "CallExpression" &&
      node.object.callee?.type === "MemberExpression") {
    const o = node.object.callee.object;
    const m = node.object.callee.property?.name;
    if (o?.type === "Identifier" && o.name === "document" &&
        /^(getElementById|querySelector|getElementsByName|getElementsByClassName|getElementsByTagName)$/.test(m || "")) {
      const readProp = node.property?.name;
      if (/^(value|innerText|innerHTML|textContent|files|dataset|src|href)$/.test(readProp || "")) {
        return true;
      }
    }
  }
  return false;
}

function exprMentionsTainted(node, tainted) {
  let found = false;
  walk.simple(node, {
    Identifier(n) { if (tainted.has(n.name)) found = true; },
  });
  return found;
}

// Single pass: gather every assignment / declaration into a list of edges.
// edge = { target: identName, sources: [exprNode], line }
// Then fixed-point: target becomes tainted if any source is tainted.
function collectEdges(ast) {
  const edges = [];

  walk.simple(ast, {
    VariableDeclarator(node) {
      if (!node.init) return;
      // Single name: const x = init
      if (node.id.type === "Identifier") {
        edges.push({
          target: node.id.name, sources: [node.init],
          line: node.loc?.start?.line ?? 0,
        });
        return;
      }
      // Destructuring: const {a, b} = init → both a and b inherit taint of init
      if (node.id.type === "ObjectPattern" || node.id.type === "ArrayPattern") {
        const names = collectPatternNames(node.id);
        for (const n of names) {
          edges.push({
            target: n, sources: [node.init],
            line: node.loc?.start?.line ?? 0,
          });
        }
      }
    },
    AssignmentExpression(node) {
      if (node.left?.type !== "Identifier") return;
      edges.push({
        target: node.left.name, sources: [node.right],
        line: node.loc?.start?.line ?? 0,
      });
    },
  });
  return edges;
}

function collectPatternNames(pat, out = []) {
  if (!pat) return out;
  if (pat.type === "Identifier") { out.push(pat.name); return out; }
  if (pat.type === "ObjectPattern") {
    for (const p of pat.properties) {
      if (p.type === "Property") collectPatternNames(p.value, out);
      else if (p.type === "RestElement") collectPatternNames(p.argument, out);
    }
  }
  if (pat.type === "ArrayPattern") {
    for (const el of pat.elements) {
      if (el) collectPatternNames(el, out);
    }
  }
  if (pat.type === "AssignmentPattern") {
    collectPatternNames(pat.left, out);
  }
  if (pat.type === "RestElement") collectPatternNames(pat.argument, out);
  return out;
}

function propagate(ast) {
  const tainted = new Set();

  // Seed: any direct source expression that IS user input -- but we collect
  // these as part of edge processing. Initial pass also covers `let x; x = ...`
  // because the AssignmentExpression edge handles it.

  const edges = collectEdges(ast);

  // First seeding pass: mark targets where source is directly user input
  for (const e of edges) {
    for (const src of e.sources) {
      if (isUserInputExpression(src)) {
        tainted.add(e.target);
      }
    }
  }

  // Fixed point -- iterate until no change. Cap at 12 iters to bound minified-code blowup.
  for (let iter = 0; iter < 12; iter++) {
    let changed = false;
    for (const e of edges) {
      if (tainted.has(e.target)) continue;
      for (const src of e.sources) {
        if (exprMentionsTainted(src, tainted)) {
          tainted.add(e.target);
          changed = true;
          break;
        }
      }
    }
    if (!changed) break;
  }

  return tainted;
}

module.exports = { propagate, isUserInputExpression };
