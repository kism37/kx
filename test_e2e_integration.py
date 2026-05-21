"""
End-to-end integration test.

Spins up a tiny in-process HTTP server that serves:
  - / (HTML referencing a JS entry bundle)
  - /assets/main-Xyz.js  (entry bundle with a chunk manifest + sourcemap ref)
  - /assets/admin-Abc.js (lazy chunk -- only discoverable via the manifest)
  - /assets/main-Xyz.js.map (sourcemap with original sources)

Then runs the full kx pipeline against it and verifies:
  - Crawler finds the entry bundle from HTML
  - Crawler discovers the lazy chunk via manifest parsing
  - Crawler recovers original sources from sourcemap
  - Semantic detectors fire on bugs in both the lazy chunk and the
    sourcemap-recovered source
"""
import asyncio
import json
import sys
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# Synthetic chunk shipping a real bug: SSRF via webhookUrl form field
LAZY_CHUNK = """
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation } from "@tanstack/react-query";

const schema = z.object({
  organizationId: z.string(),
  webhookUrl:     z.string(),
  role:           z.enum(["viewer","admin"]),
});

export default function AdminPanel({ organizationId }) {
  const { handleSubmit, control } = useForm({ resolver: zodResolver(schema) });
  const { mutate, isPending } = useMutation({
    mutationFn: (v) => fetch("/api/admin/update", { method: "POST", body: JSON.stringify(v) }),
  });
  const onSubmit = (data) => {
    mutate({ organizationId, webhookUrl: data.webhookUrl, role: data.role });
  };
  return null;
}
"""

# Entry bundle: includes a chunk manifest pointing at admin-Abc.js
# AND a sourcemap reference (so recovery is exercised).
ENTRY_BUNDLE = """
const __vite__mapDeps=(i,m=__vite__mapDeps,d=(m.f||(m.f=[
"assets/admin-Abc12345.js",
"assets/billing-Def67890.js"
])))=>i.map(i=>d[i]);
console.log("entry loaded");
//# sourceMappingURL=main-Xyz.js.map
"""

# A sourcemap with one real source (original .ts) that contains a different bug:
# client-side-only OTP validation.
SOURCEMAP = json.dumps({
    "version": 3,
    "file": "main-Xyz.js",
    "sources": [
        "webpack:///./node_modules/react/index.js",
        "webpack:///./src/auth/LoginForm.ts",
    ],
    "sourcesContent": [
        "module.exports = require('./cjs/react.production.min.js');",
        """
import { z } from "zod";
import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { useMutation } from "@tanstack/react-query";

// Client-side-only OTP validation -- server doesn't see it.
const schema = z.object({
  email:    z.string(),
  password: z.string(),
  otp:      z.string().optional(),
}).refine(d => d.otp && d.otp.length === 6, {
  message: "OTP must be 6 digits",
  path:    ["otp"],
});

export function LoginForm() {
  const { handleSubmit } = useForm({ resolver: zodResolver(schema) });
  const { mutate } = useMutation({
    mutationFn: (v) => fetch("/api/login", { method: "POST", body: JSON.stringify(v) }),
  });
  const onSubmit = (data) => {
    // Note: payload omits otp
    mutate({ email: data.email, password: data.password });
  };
  return null;
}
""",
    ],
})

INDEX_HTML = """
<!doctype html>
<html><head><title>Test target</title></head>
<body>
<script type="module" src="/assets/main-Xyz.js"></script>
</body></html>
"""

ROUTES = {
    "/":                        ("text/html", INDEX_HTML),
    "/assets/main-Xyz.js":      ("application/javascript", ENTRY_BUNDLE),
    "/assets/main-Xyz.js.map":  ("application/json", SOURCEMAP),
    "/assets/admin-Abc12345.js":("application/javascript", LAZY_CHUNK),
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a, **k): pass
    def do_GET(self):
        route = self.path.split("?")[0]
        if route not in ROUTES:
            self.send_response(404); self.end_headers(); return
        ctype, body = ROUTES[route]
        body_bytes = body.encode() if isinstance(body, str) else body
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body_bytes)))
        self.end_headers()
        self.wfile.write(body_bytes)


def serve():
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_port
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, port


async def run_test():
    from crawler import Crawler
    from classifier import run_ast, classify

    srv, port = serve()
    base = f"http://127.0.0.1:{port}/"
    print(f"Test server: {base}")

    try:
        crawler = Crawler(target=base, max_depth=3, concurrency=4, delay=0)
        results = await crawler.crawl()
    finally:
        srv.shutdown()

    print(f"\nCrawled {len(results)} resources:")
    for r in results:
        kind = "[recovered]" if r.url.startswith("sourcemap://") else "[fetched]"
        print(f"  {kind} {r.url}")

    print(f"\nSourcemap-recovered: {crawler.sourcemap_recovered}")

    js_results = [r for r in results if crawler._is_js(r.url, r.content_type)
                  or r.url.startswith("sourcemap://")]

    print(f"\nRunning AST/semantic analysis on {len(js_results)} JS files...")
    all_findings = []
    for r in js_results:
        findings = await run_ast(r.url, r.content)
        all_findings.extend(findings)

    findings = classify(all_findings)
    sem = [f for f in findings if f.category.startswith("semantic:")]
    print(f"\nSemantic findings: {len(sem)}")
    for f in sem:
        from reporter import _short_url
        print(f"  [{f.severity:8s}] {f.name[:55]:55s} → {f.match[:55]}")
        print(f"           in: {_short_url(f.source_url, 70)}")

    return findings, results


if __name__ == "__main__":
    findings, results = asyncio.run(run_test())
    # Assertions
    urls = [r.url for r in results]
    assert any("admin-Abc12345.js" in u for u in urls), "Lazy chunk not discovered via manifest!"
    assert any("sourcemap://" in u for u in urls), "Sourcemap recovery did not run!"
    assert any("LoginForm.ts" in u for u in urls), "Original sourcemap file not present!"

    sem_values = [f.match for f in findings if f.category.startswith("semantic:")]
    # We expect bugs from BOTH the lazy chunk AND the sourcemap-recovered file
    assert any("webhookUrl" in v for v in sem_values), "SSRF bug in lazy chunk not detected!"
    assert any("otp" in v for v in sem_values), "OTP bypass in sourcemap-recovered source not detected!"

    print("\n✓ All assertions passed")
