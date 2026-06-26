/**
 * kx -- Detector fixture tests
 *
 * Zero-dependency test harness (no jest/mocha): parse a JS snippet exactly the
 * way analyze.js does, build the semantic model, run the detectors, and assert
 * on the findings. Run with:  node test_detectors.js
 *
 * Covers the precision work:
 *   - boundaried ID / permission matchers (no more valid/uuid/cancel FPs)
 *   - client-only-validation disposition: omitted vs spread-likely vs absent
 *   - permission de-escalation when a role field is destructured out
 */
"use strict";

const acorn = require("acorn");
const { buildModel } = require("./semantic_model.js");
const { runDetectors, _matchers } = require("./detectors.js");
const { propagate } = require("./taint.js");

let pass = 0, fail = 0;
const failures = [];

function check(name, cond) {
  if (cond) { pass++; }
  else { fail++; failures.push(name); }
}

function parse(code) {
  try {
    return acorn.parse(code, { ecmaVersion: "latest", sourceType: "module", locations: true });
  } catch {
    return acorn.parse(code, { ecmaVersion: "latest", sourceType: "script", locations: true });
  }
}

function analyze(code) {
  const ast = parse(code);
  const model = buildModel(ast, code);
  const tainted = propagate(ast);
  return runDetectors(model, code, tainted);
}

const has = (findings, cat, value) =>
  findings.some(f => f.category === cat && (value === undefined || f.value === value));
const get = (findings, cat, value) =>
  findings.find(f => f.category === cat && (value === undefined || f.value === value));

// ───────────────────────── 1. Matcher unit tests ────────────────────────────
const { looksLikeId, looksLikeEntityId, looksLikePermission } = _matchers;

for (const k of ["id", "userId", "merchantID", "account_id", "orderId", "fooId"])
  check(`id+ ${k}`, looksLikeId(k));
for (const k of ["valid", "invalid", "paid", "uuid", "UUID", "android", "hybrid",
                 "grid", "void", "VOID", "kid", "candid", "rapid", "solid"])
  check(`id- ${k}`, !looksLikeId(k));

for (const k of ["userId", "merchantID", "account_id", "ownerId", "orderId"])
  check(`entity+ ${k}`, looksLikeEntityId(k));
for (const k of ["fooId", "widgetId", "uuid", "valid"])
  check(`entity- ${k}`, !looksLikeEntityId(k));

for (const k of ["role", "isAdmin", "tier", "admin", "whoCanChange",
                 "canChange", "canDelete", "canEscalate", "canGrant"])
  check(`perm+ ${k}`, looksLikePermission(k));
for (const k of ["cancel", "canvas", "candidate", "cannot", "canView",
                 "canCancel", "cancelReason", "cancellation", "scope", "owners"])
  check(`perm- ${k}`, !looksLikePermission(k));

// ───────────────── 2. Client-only validation: ABSENT case ───────────────────
// No spread; refine() on otp; payload omits otp entirely -> critical.
{
  const code = `
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation } from "@tanstack/react-query";
const schema = z.object({ email: z.string(), password: z.string(), otp: z.string().optional() })
  .refine(d => d.otp && d.otp.length === 6, { message: "OTP must be 6 digits", path: ["otp"] });
export function LoginForm() {
  const { handleSubmit } = useForm({ resolver: zodResolver(schema) });
  const { mutate } = useMutation({ mutationFn: (v) => fetch("/api/login", { method: "POST", body: JSON.stringify(v) }) });
  const onSubmit = (data) => { mutate({ email: data.email, password: data.password }); };
  return null;
}`;
  const fs = analyze(code);
  const f = get(fs, "auth_bypass", "otp");
  check("absent: otp flagged", !!f);
  check("absent: severity critical", f && f.severity === "critical");
  check("absent: no destructure_omit evidence", f && !f.evidence.some(e => e.kind === "destructure_omit"));
}

// ───────────────── 3. Client-only validation: OMITTED case ──────────────────
// const { authCode, ...rest } = data; mutate({ ...rest }) -> server never sees
// authCode -> critical, with destructure_omit evidence.
{
  const code = `
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation } from "@tanstack/react-query";
const schema = z.object({ email: z.string(), authCode: z.string() })
  .refine(d => d.authCode && d.authCode.length === 6, { message: "code required", path: ["authCode"] });
export function Verify() {
  const { handleSubmit } = useForm({ resolver: zodResolver(schema) });
  const { mutate } = useMutation({ mutationFn: (v) => fetch("/api/verify", { method: "POST", body: JSON.stringify(v) }) });
  const onSubmit = (data) => { const { authCode, ...rest } = data; mutate({ ...rest }); };
  return null;
}`;
  const fs = analyze(code);
  const f = get(fs, "auth_bypass", "authCode");
  check("omitted: authCode flagged", !!f);
  check("omitted: severity critical", f && f.severity === "critical");
  check("omitted: has destructure_omit evidence", f && f.evidence.some(e => e.kind === "destructure_omit"));
}

// ──────────── 4. Client-only validation: SPREAD-LIKELY (downgrade) ───────────
// Spread present, field NOT omitted, has refine -> medium "verify server".
{
  const code = `
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation } from "@tanstack/react-query";
const schema = z.object({ email: z.string(), pin: z.string() })
  .refine(d => d.pin && d.pin.length === 4, { message: "4-digit pin", path: ["pin"] });
export function Form() {
  const { handleSubmit } = useForm({ resolver: zodResolver(schema) });
  const { mutate } = useMutation({ mutationFn: (v) => fetch("/api/x", { method: "POST", body: JSON.stringify(v) }) });
  const onSubmit = (data) => { mutate({ ...data }); };
  return null;
}`;
  const fs = analyze(code);
  const f = get(fs, "auth_bypass", "pin");
  check("spread-likely: pin flagged", !!f);
  check("spread-likely: severity medium (downgraded)", f && f.severity === "medium");
}

// ───────────── 5. Permission de-escalation: role destructured out ────────────
// const { role, ...rest } = data; mutate({ ...rest }) -> role NOT sent ->
// privilege_escalation must NOT fire on role.
{
  const code = `
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation } from "@tanstack/react-query";
const schema = z.object({ name: z.string(), role: z.enum(["viewer","admin"]) });
export function Edit() {
  const { handleSubmit } = useForm({ resolver: zodResolver(schema) });
  const { mutate } = useMutation({ mutationFn: (v) => fetch("/api/u", { method: "POST", body: JSON.stringify(v) }) });
  const onSubmit = (data) => { const { role, ...rest } = data; mutate({ ...rest }); };
  return null;
}`;
  const fs = analyze(code);
  check("deescalate: role privesc NOT fired", !has(fs, "privilege_escalation", "role"));
}

// ───────────── 6. Permission still fires when role IS sent via spread ────────
{
  const code = `
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation } from "@tanstack/react-query";
const schema = z.object({ name: z.string(), role: z.enum(["viewer","admin"]) });
export function Edit() {
  const { handleSubmit } = useForm({ resolver: zodResolver(schema) });
  const { mutate } = useMutation({ mutationFn: (v) => fetch("/api/u", { method: "POST", body: JSON.stringify(v) }) });
  const onSubmit = (data) => { mutate({ ...data }); };
  return null;
}`;
  const fs = analyze(code);
  check("privesc: role fired via spread", has(fs, "privilege_escalation", "role"));
}

// ───────────── 7. Regex FP guard: cancelReason must NOT be privesc ───────────
{
  const code = `
import { useMutation } from "@tanstack/react-query";
export function C(props) {
  const { mutate } = useMutation({ mutationFn: (v) => fetch("/api/c", { method: "POST", body: JSON.stringify(v) }) });
  const go = () => { mutate({ cancelReason: props.reason, uuid: props.uuid }); };
  return null;
}`;
  const fs = analyze(code);
  check("fp-guard: cancelReason not privesc", !has(fs, "privilege_escalation", "cancelReason"));
  check("fp-guard: uuid not idor", !has(fs, "idor", "uuid"));
}

// ───────────── 8. Regex TP guard: merchantId from props IS idor ──────────────
{
  const code = `
import { useMutation } from "@tanstack/react-query";
export function P({ merchantId }) {
  const { mutate } = useMutation({ mutationFn: (v) => fetch("/api/p", { method: "POST", body: JSON.stringify(v) }) });
  const go = () => { mutate({ merchantId, amount: 100 }); };
  return null;
}`;
  const fs = analyze(code);
  check("tp-guard: merchantId fired as idor", has(fs, "idor", "merchantId"));
}

// ───────────────────────────── report ───────────────────────────────────────
console.log(`\ndetector fixtures: ${pass} passed, ${fail} failed`);
if (fail) {
  console.log("FAILURES:");
  for (const f of failures) console.log("  ✗ " + f);
  process.exit(1);
}
console.log("all detector fixtures passed ✓");
