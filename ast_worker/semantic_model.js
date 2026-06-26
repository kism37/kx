/**
 * kx -- Semantic Model Builder
 *
 * One pass over the AST that extracts every structural fact we'll later
 * reason about: form schemas, mutations/network calls, identifier sources,
 * sinks, component props, JSX renders.
 *
 * Output is a plain JS object (no AST node references) consumed by detectors.js.
 *
 * Designed to work on MINIFIED code:
 *  - Resolves import aliases (e.g. {w as zod} → "zod")
 *  - Tracks variable provenance (props vs. session vs. URL vs. state)
 *  - Handles void 0, ==null?void 0:x, optional chaining
 *
 * Author: kx
 */

"use strict";

const walk = require("acorn-walk");

// ─── helpers ────────────────────────────────────────────────────────────────

function loc(node) { return node?.loc?.start?.line ?? 0; }
function endLoc(node) { return node?.loc?.end?.line ?? 0; }

function getName(node) {
  if (!node) return null;
  if (node.type === "Identifier") return node.name;
  if (node.type === "Literal" && typeof node.value === "string") return node.value;
  if (node.type === "MemberExpression") {
    const obj = getName(node.object);
    const prop = node.property.type === "Identifier" && !node.computed
      ? node.property.name
      : getName(node.property);
    if (obj && prop) return `${obj}.${prop}`;
  }
  if (node.type === "ChainExpression") return getName(node.expression);
  return null;
}

function getStringLiteral(node) {
  if (!node) return null;
  if (node.type === "Literal" && typeof node.value === "string") return node.value;
  if (node.type === "TemplateLiteral" && node.expressions.length === 0) {
    return node.quasis.map(q => q.value.cooked).join("");
  }
  return null;
}

// Walk an object expression and return [{key, valueNode, line}, ...]
function readObjectProps(node) {
  if (!node || node.type !== "ObjectExpression") return [];
  const out = [];
  for (const p of node.properties) {
    if (p.type !== "Property") continue;
    let key = null;
    if (p.key.type === "Identifier") key = p.key.name;
    else if (p.key.type === "Literal") key = String(p.key.value);
    if (!key) continue;
    out.push({ key, valueNode: p.value, line: loc(p), shorthand: p.shorthand });
  }
  return out;
}

// Recursively collect every key name in a nested zod-ish schema object.
// Returns: [{path: "a.b.c", line, valueNode}]
function flattenSchemaFields(objNode, prefix = "", out = [], depth = 0) {
  if (depth > 12) return out;             // safety
  if (!objNode || objNode.type !== "ObjectExpression") return out;
  for (const prop of objNode.properties) {
    if (prop.type !== "Property") continue;
    let key = null;
    if (prop.key.type === "Identifier") key = prop.key.name;
    else if (prop.key.type === "Literal") key = String(prop.key.value);
    if (!key) continue;
    const path = prefix ? `${prefix}.${key}` : key;
    out.push({ path, line: loc(prop), valueNode: prop.value });
    // descend into zod() calls: w({nested:w({...})})
    if (prop.value.type === "CallExpression" &&
        prop.value.arguments[0]?.type === "ObjectExpression") {
      flattenSchemaFields(prop.value.arguments[0], path, out, depth + 1);
    }
    // descend into chained .refine().something(w({...})) -- rare
  }
  return out;
}

// Collect every dotted property access path used as an rvalue, e.g. a.b.c
function collectMemberPaths(node, out = new Set()) {
  if (!node || typeof node !== "object") return out;
  if (node.type === "MemberExpression") {
    const n = getName(node);
    if (n) out.add(n);
  }
  if (node.type === "ChainExpression") return collectMemberPaths(node.expression, out);
  for (const k of Object.keys(node)) {
    if (k === "loc" || k === "start" || k === "end" || k === "range") continue;
    const v = node[k];
    if (Array.isArray(v)) v.forEach(c => collectMemberPaths(c, out));
    else if (v && typeof v === "object" && v.type) collectMemberPaths(v, out);
  }
  return out;
}

// Collect every Identifier name read in an expression subtree
function collectIdentifiers(node, out = new Set()) {
  if (!node || typeof node !== "object") return out;
  if (node.type === "Identifier") {
    out.add(node.name);
    return out;
  }
  for (const k of Object.keys(node)) {
    if (k === "loc" || k === "start" || k === "end" || k === "range") continue;
    const v = node[k];
    if (Array.isArray(v)) v.forEach(c => collectIdentifiers(c, out));
    else if (v && typeof v === "object" && v.type) collectIdentifiers(v, out);
  }
  return out;
}

// Pull spread/property keys from an ObjectExpression payload {a, ...b, c:d}
//   returns {explicit: ["a","c"], spreads: ["b"]}
function readPayloadShape(node) {
  if (!node || node.type !== "ObjectExpression") return { explicit: [], spreads: [] };
  const explicit = [];
  const spreads = [];
  for (const p of node.properties) {
    if (p.type === "Property") {
      let k = null;
      if (p.key.type === "Identifier") k = p.key.name;
      else if (p.key.type === "Literal") k = String(p.key.value);
      if (k) explicit.push(k);
    } else if (p.type === "SpreadElement") {
      const n = getName(p.argument);
      if (n) spreads.push(n);
    }
  }
  return { explicit, spreads };
}

// Source code substring; node may have .start/.end if locations=true and ranges=true.
function snippetFor(source, node, max = 200) {
  if (!node || typeof node.start !== "number") return "";
  const s = Math.max(0, node.start - 20);
  const e = Math.min(source.length, node.end + 20);
  const text = source.slice(s, e).replace(/\s+/g, " ").trim();
  return text.length > max ? text.slice(0, max) + "..." : text;
}

// ─── known callee aliases ───────────────────────────────────────────────────
// Detectors only fire when an alias maps to a known library entrypoint.
// We resolve aliases at import time, then use them throughout.

// imported-symbol → canonical category
const KNOWN_IMPORTS = {
  // Schema validators
  zod:                    "zod",
  z:                      "zod",
  yup:                    "yup",
  joi:                    "joi",
  // Form libs
  useForm:                "form_hook",
  // Resolvers
  zodResolver:            "zod_resolver",
  yupResolver:            "yup_resolver",
  joiResolver:            "joi_resolver",
  // Mutation hooks
  useMutation:            "mutation_hook",
  useQuery:               "query_hook",
  useInfiniteQuery:       "query_hook",
  useSWR:                 "query_hook",
  useSWRMutation:         "mutation_hook",
  useLazyQuery:           "query_hook",
  // Network
  fetch:                  "fetch",
  axios:                  "axios",
  // Auth/session
  useSession:             "session_hook",
  useAuth:                "session_hook",
  useUser:                "session_hook",
  getSession:             "session_hook",
  getServerSession:       "session_hook",
  useCurrentUser:         "session_hook",
};

// String literals that imply a mutation hook by their NAME suffix.
// E.g. `useCreateMerchant`, `useUpdateAccountSettings`.
const MUTATION_HOOK_RE = /^use(Create|Update|Delete|Patch|Put|Post|Send|Submit|Save|Mutate|Sync)[A-Z]/;
const QUERY_HOOK_RE    = /^use(Get|Fetch|Read|Find|List|Load|Retrieve)[A-Z]/;
const SESSION_HOOK_RE  = /^use(Session|Auth|User|Current|Me|Account|Login|Identity)/;

// User-controllable identifier sources (used for taint)
const USER_INPUT_ROOTS = new Set([
  "location", "URLSearchParams", "FormData",
  "useParams", "useSearchParams", "useRouter",
  "router",   // next/router accessed via `router.query.X`
]);

// Properties on `location` that are user input
const LOCATION_PROPS = new Set([
  "search", "hash", "href", "pathname", "host", "hostname",
]);

// Form-field name patterns that strongly suggest sensitive purposes
const URL_FIELD_RE = /^(notification|webhook|callback|redirect|return|notify|ping|hook|forward|endpoint).*?(url|uri|endpoint|address)?$|^(.*url|.*uri|.*webhook|.*callback)$/i;
const ID_FIELD_RE  = /^(merchant|user|account|org|tenant|customer|owner|admin|user|team|workspace|project)?id$|^(merchant|user|account|org|tenant)Id$/i;
const PERMISSION_FIELD_RE = /^(role|isadmin|permission|permissions|whocanchange|accesslevel|usertype|tier|scope|grant|privilege|capability|can[a-z]+)$/i;

// ─── model builder ──────────────────────────────────────────────────────────

function buildModel(ast, source) {
  const model = {
    imports: {},            // localName → { source, importedName, category }
    schemas: {},            // varName → { line, fields: [{path, line, optional, refines: []}] }
    forms: [],              // [{ varName, resolverSchema, submitHandler, line }]
    mutations: [],          // [{ varName, hookCategory, line, payloads: [{argObject, sourceFile, line, keys, spreads, fieldsResolved}] }]
    networkCalls: [],       // [{ kind: 'fetch'|'axios.x', urlNode, bodyKeys, headers, line, urlString }]
    propsParams: {},        // function-scoped: handlerVarName → [propName,...] destructured from first arg
    sessionRefs: [],        // [{ varName, line }] -- variables derived from session hooks
    sinks: [],              // [{ kind, name, line, tainted, argExpr }]
    componentProps: [],     // [{ componentName, line, props: [{key, valueNode}] }]
    jsxRenders: [],         // [{ componentName, line, dataIdentifiers: [] }]
    sourceLength: source.length,
  };

  // ── pass 1: imports (names only -- most aliases give nothing away) ──
  walk.simple(ast, {
    ImportDeclaration(node) {
      const src = node.source.value;
      for (const spec of node.specifiers) {
        const local = spec.local.name;
        let imported = local;
        if (spec.type === "ImportSpecifier") imported = spec.imported.name;
        else if (spec.type === "ImportDefaultSpecifier") imported = "default";
        else if (spec.type === "ImportNamespaceSpecifier") imported = "*";
        let category = KNOWN_IMPORTS[imported] || null;
        if (!category) {
          if (MUTATION_HOOK_RE.test(imported)) category = "mutation_hook";
          else if (QUERY_HOOK_RE.test(imported)) category = "query_hook";
          else if (SESSION_HOOK_RE.test(imported)) category = "session_hook";
        }
        model.imports[local] = { source: src, importedName: imported, category };
      }
    },
  });

  // ── pass 1b: shape-fingerprinting for unidentified imports ──
  // Production bundlers strip identifying names. We classify by USAGE PATTERN.
  //
  // Profile collected per imported-local-name:
  //   .calls            : number of times invoked as Identifier(...)
  //   .firstArgKinds    : multiset of first-arg AST type
  //   .objArgValueKinds : when first arg is ObjectExpression, what AST types
  //                       appear as values (used to detect schema-call shape)
  //   .chainedMethods   : method names called on the return value (.refine, .optional, .parse)
  //   .destructuredFrom : if `const {a,b,...} = X()`, the destructured property names
  //   .singleArgIsKnownSchema : called as X(schemaVar) where schemaVar is a recognised schema
  //   .calledOnAsMember : count of `X.foo()` calls (used for namespace-import schemas, e.g. z.number())
  //   .memberMethodsCalled : names of `X.foo` methods called (Set)
  //   .returnFedToHookConfig : appears as the value of `resolver: X(schema)` property
  const profiles = {};
  function ensureProfile(name) {
    if (!profiles[name]) profiles[name] = {
      name,
      calls: 0,
      firstArgKinds: {},
      objArgValueKinds: {},
      objArgValueCalls: 0,
      objArgValueTotal: 0,
      chainedMethods: new Set(),
      destructuredFrom: new Set(),
      singleArgIsKnownSchema: 0,
      calledOnAsMember: 0,
      memberMethodsCalled: new Set(),
      returnFedToResolver: 0,
    };
    return profiles[name];
  }

  const importLocals = new Set(Object.keys(model.imports));

  walk.simple(ast, {
    CallExpression(node) {
      // X(...)
      if (node.callee.type === "Identifier" && importLocals.has(node.callee.name)) {
        const p = ensureProfile(node.callee.name);
        p.calls++;
        const a0 = node.arguments[0];
        const kind = a0?.type || "<none>";
        p.firstArgKinds[kind] = (p.firstArgKinds[kind] || 0) + 1;
        if (a0?.type === "ObjectExpression") {
          for (const prop of a0.properties) {
            if (prop.type !== "Property") continue;
            const vk = prop.value.type;
            p.objArgValueKinds[vk] = (p.objArgValueKinds[vk] || 0) + 1;
            p.objArgValueTotal++;
            if (vk === "CallExpression") p.objArgValueCalls++;
          }
        }
        // X(schemaVar)
        if (a0?.type === "Identifier" && model.schemas[a0.name]) {
          p.singleArgIsKnownSchema++;
        }
      }
      // X.foo(...) -- namespace-style schema usage
      if (node.callee.type === "MemberExpression" &&
          node.callee.object?.type === "Identifier" &&
          importLocals.has(node.callee.object.name) &&
          node.callee.property?.type === "Identifier") {
        const p = ensureProfile(node.callee.object.name);
        p.calledOnAsMember++;
        p.memberMethodsCalled.add(node.callee.property.name);
      }
    },
    MemberExpression(node) {
      // X(...).refine -- caller is in node.object; track method names
      // Only when object is a CallExpression on an imported alias.
      if (node.object?.type === "CallExpression" &&
          node.object.callee?.type === "Identifier" &&
          importLocals.has(node.object.callee.name) &&
          node.property?.type === "Identifier") {
        ensureProfile(node.object.callee.name).chainedMethods.add(node.property.name);
      }
      // X({...}).refine(...).refine(...) -- only the innermost is a direct call,
      // but acorn-walk's MemberExpression on intermediate nodes covers the rest.
    },
    VariableDeclarator(node) {
      // const {a,b} = X()
      if (node.id?.type === "ObjectPattern" &&
          node.init?.type === "CallExpression" &&
          node.init.callee?.type === "Identifier" &&
          importLocals.has(node.init.callee.name)) {
        const p = ensureProfile(node.init.callee.name);
        for (const prop of node.id.properties) {
          if (prop.type !== "Property") continue;
          if (prop.key?.type === "Identifier") p.destructuredFrom.add(prop.key.name);
        }
      }
    },
    Property(node) {
      // resolver: X(schemaVar) inside a useForm-style config
      if (node.key?.type === "Identifier" && node.key.name === "resolver" &&
          node.value?.type === "CallExpression" &&
          node.value.callee?.type === "Identifier" &&
          importLocals.has(node.value.callee.name)) {
        ensureProfile(node.value.callee.name).returnFedToResolver++;
      }
    },
  });

  // Now classify each profile and inject categories back into model.imports.
  // Each rule is conservative -- we only override when fingerprint is strong.
  for (const [name, p] of Object.entries(profiles)) {
    const cur = model.imports[name];
    if (!cur) continue;
    if (cur.category) continue; // already known by name

    // SCHEMA validator fingerprint:
    //   X({...}) where most-or-all object values are CallExpressions
    //   AND chained methods include refine/optional/parse/safeParse
    const schemaChainHits = ["refine", "optional", "parse", "safeParse", "extend", "merge"]
      .filter(m => p.chainedMethods.has(m)).length;
    const objValueCallRatio = p.objArgValueTotal > 0
      ? p.objArgValueCalls / p.objArgValueTotal : 0;
    if (
      p.calls >= 1 &&
      p.firstArgKinds.ObjectExpression >= 1 &&
      objValueCallRatio >= 0.7 &&
      schemaChainHits >= 1
    ) {
      cur.category = "zod"; // category label kept generic -- same downstream code path
      continue;
    }

    // NAMESPACE schema (z.number(), z.string(), etc):
    //   alias is used primarily as X.foo() and foo includes typical primitives
    const primitiveMethods = ["number","string","boolean","array","object","union","enum","literal","date","record"];
    const namespaceHits = primitiveMethods.filter(m => p.memberMethodsCalled.has(m)).length;
    if (p.calledOnAsMember >= 2 && namespaceHits >= 1) {
      cur.category = "zod_namespace";
      continue;
    }

    // RESOLVER fingerprint:
    //   X(schemaVar) -- called with a single arg that resolves to a known schema
    //   AND its return value lives as a `resolver:` property
    if (p.singleArgIsKnownSchema >= 1 && p.returnFedToResolver >= 1) {
      cur.category = "zod_resolver";
      continue;
    }
    // Even without the schema resolution being seen yet, a single-arg function
    // whose return goes to a `resolver:` slot is the resolver.
    if (p.returnFedToResolver >= 1) {
      cur.category = "zod_resolver";
      continue;
    }

    // FORM hook fingerprint:
    //   react-hook-form:  {handleSubmit, control, watch, setValue, register, formState, ...}
    //   vee-validate:     {handleSubmit, values, errors, defineField, meta}
    //   svelte sveltekit-superforms: {form, enhance, errors, message}
    const formMarkers = [
      "handleSubmit","control","watch","setValue","register","formState",
      "resetField","getValues","values","errors","defineField","meta",
      "validate","setError","clearErrors","enhance"
    ];
    const formHits = formMarkers.filter(m => p.destructuredFrom.has(m)).length;
    // handleSubmit + one more marker is a strong fingerprint
    if (p.destructuredFrom.has("handleSubmit") && formHits >= 2) {
      cur.category = "form_hook";
      continue;
    }
    if (formHits >= 3) {
      cur.category = "form_hook";
      continue;
    }

    // MUTATION hook fingerprint:
    //   const {mutate(Async)?, is(Pending|Loading), ...} = X(...)
    const mutMarkers = ["mutate","mutateAsync","isPending","isLoading","isError","isSuccess"];
    const mutHits = mutMarkers.filter(m => p.destructuredFrom.has(m)).length;
    if ((p.destructuredFrom.has("mutate") || p.destructuredFrom.has("mutateAsync")) && mutHits >= 2) {
      cur.category = "mutation_hook";
      continue;
    }

    // QUERY hook fingerprint:
    //   const {data, isLoading|isPending|error, ...} = X(...)
    const queryMarkers = ["data","isLoading","isPending","error","refetch","isFetching"];
    const queryHits = queryMarkers.filter(m => p.destructuredFrom.has(m)).length;
    if (p.destructuredFrom.has("data") && queryHits >= 2) {
      cur.category = "query_hook";
      continue;
    }

    // SESSION hook fingerprint:
    //   const {data: s, status} = X()       (next-auth style)
    //   const {user, ...} = X()             (auth0/clerk style)
    //   const {session, ...} = X()
    if (p.destructuredFrom.has("status") && p.destructuredFrom.has("data") &&
        p.calls >= 1 && Object.keys(p.firstArgKinds).every(k => k === "<none>")) {
      cur.category = "session_hook";
      continue;
    }
    if ((p.destructuredFrom.has("user") || p.destructuredFrom.has("session")) &&
        p.calls >= 1) {
      cur.category = "session_hook";
      continue;
    }
  }

  // For the IMPORTANT case where the file uses a namespace-style call like
  // Ca.number().optional() -- register the alias's category but the rest of
  // the model below mostly checks "is alias zod-shape?". Both "zod" and
  // "zod_namespace" should be treated equivalently when classifying schemas:
  // schemas are still defined by the `w({...}).refine(...)` form, not by
  // `Ca.number()`. So zod_namespace is informational; the schema-detection
  // pass below uses the "zod" category exclusively.

  // Quick lookup: is `name` an alias for a known category?
  const aliasCategory = (name) =>
    name && model.imports[name] ? model.imports[name].category : null;

  // Reverse lookup: get every local alias whose category matches
  const aliasesFor = (cat) =>
    Object.entries(model.imports)
      .filter(([, info]) => info.category === cat)
      .map(([local]) => local);

  const zodAliases       = new Set(aliasesFor("zod"));
  const formHookAliases  = new Set(aliasesFor("form_hook"));
  const sessionAliases   = new Set(aliasesFor("session_hook"));
  const mutationAliases  = new Set(aliasesFor("mutation_hook"));
  const queryAliases     = new Set(aliasesFor("query_hook"));

  // ── pass 2: variable declarations ──
  //   - schemas: const X = z({...}) or z({...}).refine(...).refine(...)
  //   - mutations: const {mutate: M} = useMutation(...) OR  const M = useUpdateThing()
  //   - sessions:  const {data: s} = useSession()
  //   - forms:     const {handleSubmit, control, ...} = useForm({resolver: zodResolver(X)})
  //   - props:     const {a, b} = props on component param destructuring (handled in pass 3)
  walk.simple(ast, {
    VariableDeclarator(node) {
      if (!node.init) return;

      // Unwrap chained .refine() / .optional() etc → get the root call.
      // BUT preserve namespace-style schema heads like z.object({...}).
      // Stop unwrapping when the property is "object" (the schema constructor),
      // or when the next layer's callee is a plain Identifier.
      let root = node.init;
      // If the init is a wrapping adapter like toTypedSchema(z.object(...)),
      // unwrap one layer: if root is a CallExpression with exactly one arg
      // that's itself a CallExpression (potentially nested), peel one level
      // only when the inner call looks like a schema.
      if (root.type === "CallExpression" &&
          root.callee.type === "Identifier" &&
          root.arguments.length === 1 &&
          root.arguments[0]?.type === "CallExpression") {
        const inner = root.arguments[0];
        const isInnerSchema =
          (inner.callee.type === "Identifier" && zodAliases.has(inner.callee.name)) ||
          (inner.callee.type === "MemberExpression" &&
           inner.callee.object?.type === "Identifier" &&
           inner.callee.property?.name === "object" &&
           ["zod_namespace","zod"].includes(model.imports[inner.callee.object.name]?.category));
        if (isInnerSchema) root = inner;
      }
      while (root.type === "CallExpression" &&
             root.callee.type === "MemberExpression" &&
             root.callee.object) {
        // If THIS level is X.object(...), keep it -- it's the schema constructor.
        if (root.callee.property?.name === "object") break;
        root = root.callee.object;
      }
      // If unwrapped to a Call, check the callee name
      if (root.type === "CallExpression") {
        // Two valid shapes:
        //   1. zod-like:  X({...}).refine(...)         -- callee is an Identifier
        //   2. namespace: z.object({...}).refine(...)  -- callee is a MemberExpression
        //      where object is an Identifier of category zod/zod_namespace and
        //      property is "object".
        let calleeName = null;
        let isSchemaCall = false;

        if (root.callee.type === "Identifier") {
          calleeName = root.callee.name;
          if (calleeName && zodAliases.has(calleeName) &&
              root.arguments[0]?.type === "ObjectExpression") {
            isSchemaCall = true;
          }
        } else if (root.callee.type === "MemberExpression" &&
                   root.callee.object?.type === "Identifier" &&
                   root.callee.property?.name === "object") {
          const ns = root.callee.object.name;
          const cat = model.imports[ns]?.category;
          if ((cat === "zod_namespace" || cat === "zod") &&
              root.arguments[0]?.type === "ObjectExpression") {
            isSchemaCall = true;
            calleeName = ns;
          }
        }

        // Schema definition
        if (isSchemaCall) {
          // Only top-level definitions get registered
          if (node.id.type === "Identifier") {
            const fields = flattenSchemaFields(root.arguments[0]);
            // Capture .refine() messages from the ORIGINAL init chain
            const refines = [];
            let cur = node.init;
            while (cur.type === "CallExpression" &&
                   cur.callee.type === "MemberExpression" &&
                   cur.callee.property.name === "refine") {
              const msgNode = cur.arguments[1];
              const pathProp = msgNode?.type === "ObjectExpression"
                ? msgNode.properties.find(p => p.key?.name === "path")
                : null;
              const pathVal = pathProp?.value?.type === "ArrayExpression"
                ? pathProp.value.elements.map(getStringLiteral).filter(Boolean).join(".")
                : null;
              const msgProp = msgNode?.type === "ObjectExpression"
                ? msgNode.properties.find(p => p.key?.name === "message")
                : null;
              refines.push({
                path: pathVal,
                message: getStringLiteral(msgProp?.value) || null,
                checkSnippet: snippetFor(source, cur.arguments[0], 160),
                line: loc(cur),
              });
              cur = cur.callee.object;
            }
            model.schemas[node.id.name] = { line: loc(node), fields, refines };
          }
        }

        // Mutation hook usage:  useXxx()  or  useMutation({...})
        if (calleeName && (mutationAliases.has(calleeName) ||
                           queryAliases.has(calleeName))) {
          const hookCat = aliasCategory(calleeName);

          // Destructured: const {mutate: M} = useMutation(...)
          if (node.id.type === "ObjectPattern") {
            for (const p of node.id.properties) {
              if (p.type !== "Property") continue;
              const local = p.value.type === "Identifier" ? p.value.name : null;
              const original = p.key.type === "Identifier" ? p.key.name : null;
              if (local && original === "mutate") {
                model.mutations.push({
                  varName: local, hookCategory: hookCat,
                  line: loc(node), payloads: [],
                  hookAlias: calleeName,
                });
              }
            }
          }
          // Direct: const M = useUpdateThing()
          else if (node.id.type === "Identifier" && hookCat === "mutation_hook") {
            model.mutations.push({
              varName: node.id.name, hookCategory: hookCat,
              line: loc(node), payloads: [],
              hookAlias: calleeName,
            });
          }
        }

        // Session hook
        if (calleeName && sessionAliases.has(calleeName)) {
          if (node.id.type === "Identifier") {
            model.sessionRefs.push({ varName: node.id.name, line: loc(node) });
          } else if (node.id.type === "ObjectPattern") {
            for (const p of node.id.properties) {
              if (p.type !== "Property") continue;
              const local = p.value.type === "Identifier" ? p.value.name : null;
              if (local) model.sessionRefs.push({ varName: local, line: loc(node) });
            }
          }
        }

        // useForm({resolver: zodResolver(schema)})       -- react-hook-form
        // useForm({validationSchema: schema})              -- vee-validate
        // useForm({schema})                                -- svelte-forms-lib / others
        if (calleeName && formHookAliases.has(calleeName)) {
          const cfg = root.arguments[0];
          let resolverSchema = null;
          if (cfg?.type === "ObjectExpression") {
            // Try {resolver: someResolverFn(schemaVar)} pattern
            const rprop = cfg.properties.find(
              p => p.type === "Property" && p.key?.name === "resolver"
            );
            if (rprop?.value?.type === "CallExpression" &&
                rprop.value.arguments[0]?.type === "Identifier") {
              resolverSchema = rprop.value.arguments[0].name;
            }
            // Try {validationSchema: schemaVar} pattern
            if (!resolverSchema) {
              const vprop = cfg.properties.find(
                p => p.type === "Property" &&
                     /^(validationSchema|schema)$/.test(p.key?.name || "")
              );
              if (vprop?.value?.type === "Identifier") {
                resolverSchema = vprop.value.name;
              }
            }
          }
          // Capture destructured names like {handleSubmit, control, ...}
          const destructured = [];
          if (node.id.type === "ObjectPattern") {
            for (const p of node.id.properties) {
              if (p.type === "Property") {
                const local = p.value.type === "Identifier" ? p.value.name : null;
                const original = p.key.type === "Identifier" ? p.key.name : null;
                if (local && original) destructured.push({ original, local });
              }
            }
          }
          model.forms.push({
            line: loc(node),
            resolverSchema,
            destructured,
            hookAlias: calleeName,
          });
        }
      }
    },
  });

  // ── pass 2b: resolve schema-to-schema references ──
  // Real code reuses schemas: const K = w({...}); const ua = w({foo: K, ...})
  // The first pass records `foo` as a field with no nested children. Now we
  // re-walk every schema; wherever a field's valueNode is an Identifier
  // referring to another schema, splice that schema's fields inline.
  for (const schemaName of Object.keys(model.schemas)) {
    const s = model.schemas[schemaName];
    const expanded = [];
    const seen = new Set(); // avoid cycles
    function expandField(f, prefix = "", depth = 0) {
      if (depth > 10) return;
      const path = prefix ? `${prefix}.${f.path.replace(/^[^.]*\./, "") || f.path}` : f.path;
      expanded.push({ ...f, path });
      const v = f.valueNode;
      // Identifier referencing another schema
      if (v?.type === "Identifier" && model.schemas[v.name] && !seen.has(v.name)) {
        seen.add(v.name);
        const inner = model.schemas[v.name];
        for (const innerField of inner.fields) {
          expandField(
            { ...innerField, path: innerField.path, line: f.line, valueNode: innerField.valueNode },
            path, depth + 1
          );
        }
        seen.delete(v.name);
      }
    }
    for (const f of s.fields) expandField(f);
    // De-dup by path (a field and its sub-paths can collide if both passes hit)
    const byPath = new Map();
    for (const f of expanded) {
      if (!byPath.has(f.path)) byPath.set(f.path, f);
    }
    s.fields = [...byPath.values()];
  }

  // Also handle pattern where mutation comes from custom hook called inline:
  //   const ma = Na();      // Na is imported, but maybe not categorized
  //   ...
  //   ma({merchantID:t,...ce})
  // We need to mark ANY call we later see being called with an object literal
  // payload as a "candidate mutation". We do this in pass 3.

  // ── pass 3: component param destructuring (props) + nested handlers ──
  // Capture every function/arrow whose first param is an ObjectPattern.
  // That's how minified components expose props: ({isMerchant:r, merchantID:da}) => {...}
  const fnParamProps = []; // [{paramIdMap: {localName: originalName}, line, scope: nodeRef}]
  walk.ancestor(ast, {
    ArrowFunctionExpression(node) { captureParamProps(node); },
    FunctionExpression(node)     { captureParamProps(node); },
    FunctionDeclaration(node)    { captureParamProps(node); },
  });
  function captureParamProps(fn) {
    if (!fn.params?.length) return;
    const p = fn.params[0];
    if (p.type !== "ObjectPattern") return;
    const idMap = {};
    for (const pr of p.properties) {
      if (pr.type !== "Property") continue;
      const original = pr.key.type === "Identifier" ? pr.key.name : null;
      const local = pr.value.type === "Identifier"
        ? pr.value.name
        : (pr.value.type === "AssignmentPattern" && pr.value.left.type === "Identifier"
            ? pr.value.left.name
            : null);
      if (original && local) idMap[local] = original;
    }
    if (Object.keys(idMap).length) {
      fnParamProps.push({ idMap, line: loc(fn), fnNode: fn });
    }
  }

  // Flatten all known "original names" of variables from props
  const propOriginByLocal = {};
  for (const f of fnParamProps) {
    for (const [local, original] of Object.entries(f.idMap)) {
      // First-write-wins (outer scope usually right)
      if (!propOriginByLocal[local]) propOriginByLocal[local] = original;
    }
  }

  // ── pass 3b: local-variable origin propagation ──
  // Real code rarely has `mut({merchantID: props.x})` -- there's always an
  // intermediate `const t = props.x || fallback;` Then `mut({merchantID: t})`.
  // Walk every VariableDeclarator and assignment; tag each local with the
  // strongest origin we can infer.
  //
  // Map: localVarName → originType
  //   "prop"        -- directly == a prop alias
  //   "prop_member" -- accessed via a prop's member (i.merchantID)
  //   "prop_chain"  -- same but via ?. or ==null?void 0:x.foo (minified)
  //   "user_input"  -- from location/URL/etc.
  //   "session"     -- from a session ref
  //   "literal"     -- string/number/bool literal
  //   "unknown"     -- fell through
  const sessionVarNames = new Set(model.sessionRefs.map(s => s.varName));
  const localOrigins = {};
  // Track object-literal assignments so mutations called with an Identifier
  // argument can resolve to the original ObjectExpression.
  //   const payload = {a:1, b:2};
  //   mut(payload);
  // → mutation walker can read keys from `localObjects.payload`.
  const localObjects = {};

  function classifyExpr(node) {
    if (!node) return { type: "unknown" };
    // Literal
    if (node.type === "Literal") return { type: "literal" };
    // Identifier
    if (node.type === "Identifier") {
      if (propOriginByLocal[node.name]) return { type: "prop", name: node.name };
      if (sessionVarNames.has(node.name)) return { type: "session", name: node.name };
      if (localOrigins[node.name]) return { type: localOrigins[node.name].type, name: node.name };
      return { type: "local", name: node.name };
    }
    // MemberExpression -- chase the root identifier
    if (node.type === "MemberExpression") {
      const root = rootIdentifier(node);
      if (!root) return { type: "unknown" };
      if (propOriginByLocal[root]) return { type: "prop_member", name: getName(node) || root };
      if (root === "location" || root === "window") return { type: "user_input", name: getName(node) };
      if (sessionVarNames.has(root)) return { type: "session", name: getName(node) };
      // x?.y minified to "x==null?void 0:x.y"
      if (localOrigins[root]) {
        const lo = localOrigins[root];
        return { type: lo.type, name: getName(node) || root };
      }
      return { type: "local_member", name: getName(node) };
    }
    // ChainExpression: a?.b
    if (node.type === "ChainExpression") return classifyExpr(node.expression);
    // LogicalExpression: x || y (most common: prop || default)
    if (node.type === "LogicalExpression") {
      const l = classifyExpr(node.left);
      const r = classifyExpr(node.right);
      // Prefer the stronger non-literal one.
      if (l.type !== "unknown" && l.type !== "literal") return { ...l, type: l.type + "_or_default" };
      if (r.type !== "unknown" && r.type !== "literal") return r;
      return l.type !== "unknown" ? l : r;
    }
    // Conditional / ?: -- common in minified null-checks
    //   i==null?void 0:i.merchantID
    if (node.type === "ConditionalExpression") {
      // Skip "==null?void 0:..." chain -- classify the alternate branch
      const alt = classifyExpr(node.alternate);
      const cons = classifyExpr(node.consequent);
      // Prefer non-undefined branch
      if (alt.type !== "unknown" && alt.type !== "literal") return alt;
      return cons;
    }
    // BinaryExpression: concatenation, etc. Take whichever side is most-tainted.
    if (node.type === "BinaryExpression") {
      const l = classifyExpr(node.left);
      const r = classifyExpr(node.right);
      const stronger = ["user_input","prop","prop_member","prop_chain","session"];
      for (const s of stronger) {
        if (l.type === s) return l;
        if (r.type === s) return r;
      }
      return { type: "unknown" };
    }
    // CallExpression: x = f(args). Generally preserves taint of args.
    if (node.type === "CallExpression") {
      for (const a of node.arguments) {
        const c = classifyExpr(a);
        if (c.type === "user_input" || c.type === "prop" ||
            c.type === "prop_member" || c.type === "prop_chain") {
          return c;
        }
      }
      return { type: "unknown" };
    }
    // ObjectExpression: a fresh object. Cannot be a prop itself.
    return { type: "unknown" };
  }

  // Two passes for fixed point -- second pass picks up forward references
  for (let iter = 0; iter < 2; iter++) {
    walk.simple(ast, {
      VariableDeclarator(node) {
        if (!node.init || node.id.type !== "Identifier") return;
        // Capture object-literal aliases for mutation-payload resolution.
        if (node.init.type === "ObjectExpression") {
          if (!localObjects[node.id.name]) localObjects[node.id.name] = node.init;
        }
        const c = classifyExpr(node.init);
        if (c.type === "unknown") return;
        // Don't downgrade -- keep stronger info
        if (!localOrigins[node.id.name] || localOrigins[node.id.name].type === "unknown") {
          localOrigins[node.id.name] = c;
        }
      },
    });
  }

  // ── pass 4: mutation invocations & generic candidate calls ──
  // For every CallExpression where callee is an Identifier registered as a mutation,
  // capture the first argument as a payload.
  // Also capture "candidate" mutation calls: any local-bound function that takes an
  // ObjectExpression as first arg AND comes from a known mutation/query hook category.

  const mutationVarMap = {};
  for (const m of model.mutations) mutationVarMap[m.varName] = m;

  walk.simple(ast, {
    CallExpression(node) {
      const callee = node.callee;
      const calleeName = callee.type === "Identifier" ? callee.name : null;
      if (!calleeName) return;

      // Direct mutation call: ma({...}) or ma(payloadVar)
      const mut = mutationVarMap[calleeName];
      if (mut) {
        const a0 = node.arguments[0];
        let payloadObj = null;
        if (a0?.type === "ObjectExpression") {
          payloadObj = a0;
        } else if (a0?.type === "Identifier" && localObjects[a0.name]) {
          // Resolve `mut(payload)` → the ObjectExpression payload was bound to.
          payloadObj = localObjects[a0.name];
        }
        if (payloadObj) {
          const shape = readPayloadShape(payloadObj);
          const fieldsResolved = resolvePayloadFields(
            payloadObj, propOriginByLocal, model.schemas, localOrigins
          );
          mut.payloads.push({
            line: loc(node),
            keys: shape.explicit,
            spreads: shape.spreads,
            fieldsResolved,
            snippet: snippetFor(source, node, 240),
            argNode: payloadObj,
            indirect: a0.type === "Identifier" ? a0.name : null,
          });
        }
      }
    },
  });

  // ── pass 5: network calls -- fetch, axios.<x>(url, options) ──
  walk.simple(ast, {
    CallExpression(node) {
      const callee = node.callee;
      // fetch(url, opts)
      if (callee.type === "Identifier" && callee.name === "fetch") {
        recordNetworkCall(node, "fetch", node.arguments[0], node.arguments[1]);
      }
      // axios(...), axios.get/post/put/patch/delete(url, body|opts, [opts])
      if (callee.type === "MemberExpression") {
        const objName = callee.object.type === "Identifier" ? callee.object.name : null;
        const method = callee.property.type === "Identifier" ? callee.property.name : null;
        const httpVerbs = new Set(["get","post","put","patch","delete","request"]);
        if (objName && method && httpVerbs.has(method.toLowerCase()) &&
            (objName === "axios" || objName === "http" || objName === "api" || objName === "client")) {
          recordNetworkCall(node, `${objName}.${method}`, node.arguments[0],
                            node.arguments[1] || node.arguments[2]);
        }
      }
    },
  });
  function recordNetworkCall(node, kind, urlNode, optsOrBodyNode) {
    const urlString = getStringLiteral(urlNode);
    let bodyKeys = [];
    let bodyNode = null;
    if (optsOrBodyNode?.type === "ObjectExpression") {
      // First, try to interpret this object as a fetch-style options object.
      // If it has a `body` property, prefer its inner shape; the outer
      // {method, body, headers} keys are options, not payload keys.
      const bodyProp = optsOrBodyNode.properties.find(
        p => p.type === "Property" && p.key?.name === "body"
      );
      const looksLikeFetchOpts = bodyProp ||
        optsOrBodyNode.properties.some(p =>
          p.type === "Property" && /^(method|headers|credentials|mode|signal|cache|redirect|referrer)$/i.test(p.key?.name || ""));

      if (bodyProp) {
        // body: JSON.stringify(X) | X | JSON.stringify({...})
        let bv = bodyProp.value;
        if (bv?.type === "CallExpression") bv = bv.arguments[0];
        if (bv?.type === "ObjectExpression") {
          bodyKeys = readPayloadShape(bv).explicit;
          bodyNode = bv;
        } else if (bv?.type === "Identifier" && localObjects[bv.name]) {
          bodyKeys = readPayloadShape(localObjects[bv.name]).explicit;
          bodyNode = localObjects[bv.name];
        }
      } else if (!looksLikeFetchOpts) {
        // axios.post(url, body) -- body is the raw object
        const shape = readPayloadShape(optsOrBodyNode);
        bodyKeys = shape.explicit;
        bodyNode = optsOrBodyNode;
      }
    } else if (optsOrBodyNode?.type === "Identifier" && localObjects[optsOrBodyNode.name]) {
      // axios.post(url, payloadVar) -- resolve indirectly
      bodyKeys = readPayloadShape(localObjects[optsOrBodyNode.name]).explicit;
      bodyNode = localObjects[optsOrBodyNode.name];
    }
    model.networkCalls.push({
      kind, line: loc(node), urlString,
      urlIdentifiers: [...collectIdentifiers(urlNode || {})],
      urlMemberPaths: [...collectMemberPaths(urlNode || {})],
      bodyKeys, bodyNode,
    });
  }

  // ── pass 6: sinks ── (kept compatible with existing analyze.js detectors)
  walk.simple(ast, {
    CallExpression(node) {
      const callee = node.callee;
      const name = callee.type === "Identifier" ? callee.name : null;
      if (["eval", "Function"].includes(name)) {
        model.sinks.push({
          kind: "call", name: `${name}()`, line: loc(node),
          argSnippet: snippetFor(source, node.arguments[0], 160),
          argNode: node.arguments[0],
        });
      }
    },
    AssignmentExpression(node) {
      if (node.left?.type !== "MemberExpression") return;
      const prop = node.left.property?.name;
      if (["innerHTML","outerHTML","insertAdjacentHTML"].includes(prop)) {
        model.sinks.push({
          kind: "assignment", name: `${prop} =`, line: loc(node),
          argSnippet: snippetFor(source, node.right, 160),
          argNode: node.right,
        });
      }
    },
  });

  // ── pass 7: rest-omission capture ──
  // const { authCode, captcha, ...rest } = values;  -> `rest` deliberately
  // omits authCode & captcha. If `rest` is later spread into a payload, those
  // fields are provably NOT transmitted. This is the strongest possible signal
  // for client-only validation (server never sees the field) AND a privilege-
  // escalation *de-escalator* (an omitted permission field can't be set by the
  // client through that payload). Captured here so detectors can reason about it.
  const restOmissions = {};   // restVarName -> { omitted: Set<string>, fromVar }
  walk.simple(ast, {
    VariableDeclarator(node) {
      if (node.id?.type !== "ObjectPattern") return;
      const rest = node.id.properties.find(p => p.type === "RestElement");
      if (!rest || rest.argument?.type !== "Identifier") return;
      const omitted = new Set();
      for (const p of node.id.properties) {
        if (p.type !== "Property") continue;
        const k = p.key?.type === "Identifier" ? p.key.name
                : p.key?.type === "Literal" ? String(p.key.value) : null;
        if (k) omitted.add(k);
      }
      const fromVar = node.init?.type === "Identifier" ? node.init.name : null;
      const prev = restOmissions[rest.argument.name];
      if (prev) for (const k of omitted) prev.omitted.add(k);
      else restOmissions[rest.argument.name] = { omitted, fromVar };
    },
  });
  model.restOmissions = restOmissions;

  model.propOriginByLocal = propOriginByLocal;
  model.localOrigins = localOrigins;
  return model;
}

// Given a mutation payload ObjectExpression, figure out where each key's
// value originates: a prop, session, URL, state, literal, etc.
//
// `localOrigins` carries one-hop variable resolution: const t = i.merchantID;
// then `mut({merchantID: t})` → t resolves to prop_member.
function resolvePayloadFields(objNode, propOriginByLocal, schemas, localOrigins = {}) {
  const out = []; // [{key, originType, originName}]
  for (const p of objNode.properties) {
    if (p.type === "SpreadElement") {
      const spreadId = p.argument.type === "Identifier" ? p.argument.name : null;
      let originType = "spread";
      if (spreadId) {
        if (propOriginByLocal[spreadId]) originType = "prop_spread";
        else if (localOrigins[spreadId]) originType = localOrigins[spreadId].type + "_spread";
      }
      out.push({
        key: "...", originType, originName: spreadId, spreadFrom: spreadId,
      });
      continue;
    }
    if (p.type !== "Property") continue;
    const key = p.key.type === "Identifier" ? p.key.name
              : p.key.type === "Literal" ? String(p.key.value) : null;
    if (!key) continue;

    let originType = "unknown";
    let originName = null;
    const v = p.value;

    if (v.type === "Literal") originType = "literal";
    else if (v.type === "Identifier") {
      originName = v.name;
      if (propOriginByLocal[v.name]) originType = "prop";
      else if (localOrigins[v.name]) {
        originType = localOrigins[v.name].type;
        originName = localOrigins[v.name].name || v.name;
      } else {
        originType = "local";
      }
    } else if (v.type === "LogicalExpression") {
      // x || y -- most common: prop || default
      const left = v.left;
      if (left.type === "Identifier") {
        if (propOriginByLocal[left.name]) { originType = "prop_or_default"; originName = left.name; }
        else if (localOrigins[left.name]) {
          originType = localOrigins[left.name].type + "_or_default";
          originName = localOrigins[left.name].name || left.name;
        }
      } else if (left.type === "MemberExpression") {
        const root = rootIdentifier(left);
        if (root && propOriginByLocal[root]) {
          originType = "prop_member"; originName = getName(left);
        } else if (root === "location") {
          originType = "user_input"; originName = getName(left);
        }
      }
    } else if (v.type === "MemberExpression") {
      const root = rootIdentifier(v);
      const path = getName(v);
      if (root && propOriginByLocal[root]) {
        originType = "prop_member"; originName = path;
      } else if (root === "location") {
        originType = "user_input"; originName = path;
      } else if (root && /^use(Params|SearchParams|Router)$/.test(root)) {
        originType = "user_input"; originName = path;
      } else if (root && localOrigins[root]) {
        originType = localOrigins[root].type + "_member";
        originName = path;
      }
    } else if (v.type === "ChainExpression") {
      // ?. -- same idea, recurse
      const inner = v.expression;
      if (inner.type === "MemberExpression") {
        const root = rootIdentifier(inner);
        const path = getName(inner);
        if (root && propOriginByLocal[root]) {
          originType = "prop_member"; originName = path;
        }
      }
    } else if (v.type === "ConditionalExpression") {
      // i==null?void 0:i.merchantID -- classify alternate branch
      const alt = v.alternate;
      if (alt?.type === "MemberExpression") {
        const root = rootIdentifier(alt);
        if (root && propOriginByLocal[root]) {
          originType = "prop_member"; originName = getName(alt);
        } else if (root && localOrigins[root]) {
          originType = localOrigins[root].type + "_member"; originName = getName(alt);
        }
      }
    }

    out.push({ key, originType, originName });
  }
  return out;
}

function rootIdentifier(node) {
  let cur = node;
  while (cur && cur.type === "MemberExpression") cur = cur.object;
  if (cur && cur.type === "ChainExpression") cur = cur.expression;
  while (cur && cur.type === "MemberExpression") cur = cur.object;
  return cur?.type === "Identifier" ? cur.name : null;
}

module.exports = {
  buildModel,
  flattenSchemaFields,
  readPayloadShape,
  // exported for unit tests
  _internal: { getName, getStringLiteral, rootIdentifier },
};
