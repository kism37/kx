"""
kx -- Burp Suite Integration
Pushes discovered endpoints into Burp's sitemap via the REST API.
Requires Burp's REST API enabled: Proxy > Options > REST API
"""

import httpx
from extractor import Finding


async def push_to_burp(
    findings: list[Finding],
    runtime_urls: list[str],
    burp_url: str = "http://127.0.0.1:1337",
    api_key: str | None = None,
) -> dict:
    """
    Push endpoints and interesting URLs to Burp sitemap.
    Returns summary of what was sent.
    """
    # Collect unique endpoint URLs from findings
    endpoint_urls: set[str] = set()

    for f in findings:
        if f.category in ("endpoints", "ast:endpoint"):
            match = f.match.strip().strip("`\"'")
            if match.startswith("http"):
                endpoint_urls.add(match)
            elif match.startswith("/"):
                # Relative path -- we don't have the base here, skip
                pass

    endpoint_urls.update(runtime_urls)

    if not endpoint_urls:
        return {"sent": 0, "error": None}

    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    sent = 0
    errors = []

    async with httpx.AsyncClient(timeout=5.0) as client:
        for url in endpoint_urls:
            try:
                # Burp REST API: add URL to scope/sitemap
                resp = await client.post(
                    f"{burp_url}/v0.1/scanner/scans",
                    json={"urls": [url]},
                    headers=headers,
                )
                if resp.status_code < 400:
                    sent += 1
            except Exception as e:
                errors.append(str(e))

    return {"sent": sent, "errors": errors[:5]}
