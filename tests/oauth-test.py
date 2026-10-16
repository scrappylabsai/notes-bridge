#!/usr/bin/env python3
"""OAuth door e2e. usage: oauth-test.py BASE AGENT_TOKEN [expect_agent] [mint=0|1]
mint=1 runs the full code → token → REST/MCP flow (mints real tokens: scratch instance only).
mint=0 checks discovery, the 401 header, the approval page and the deny paths — safe on the public URL.
Env: HOST (an allowed redirect host from policy.json, default claude.ai)."""
import asyncio, base64, hashlib, json, os, secrets, sys
from urllib.parse import parse_qs, urlsplit
import httpx

BASE, TOK = sys.argv[1].rstrip("/"), sys.argv[2]
rest = [a for a in sys.argv[3:] if a not in ("0", "1")]
AGENT = rest[0] if rest else None
MINT = "1" in sys.argv[3:]
HOST = os.environ.get("HOST", "claude.ai")
P = F = 0


def chk(name, ok, extra=""):
    global P, F
    ok = bool(ok); P += ok; F += (not ok)
    print(("PASS " if ok else "FAIL ") + name, extra)


def b64url(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


c = httpx.Client(timeout=20, follow_redirects=False)
r = c.get(f"{BASE}/.well-known/oauth-protected-resource"); pr = r.json() if r.status_code == 200 else {}
chk("protected-resource", r.status_code == 200 and pr.get("resource", "").endswith("/mcp") and pr.get("authorization_servers"), pr.get("authorization_servers"))
r = c.get(f"{BASE}/.well-known/oauth-authorization-server"); am = r.json() if r.status_code == 200 else {}
chk("as-metadata", r.status_code == 200 and am.get("code_challenge_methods_supported") == ["S256"] and "none" in am.get("token_endpoint_auth_methods_supported", []), am.get("issuer"))
local = lambda u: BASE + urlsplit(u).path   # metadata names the public issuer; talk to BASE
AUTHZ, TOKEN_EP, REG, REVOKE = (local(am.get(k, "")) for k in ("authorization_endpoint", "token_endpoint", "registration_endpoint", "revocation_endpoint"))
r = c.post(f"{BASE}/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "initialize"}, headers={"Accept": "application/json, text/event-stream"})
chk("401-resource-metadata", r.status_code == 401 and "resource_metadata=" in r.headers.get("www-authenticate", ""), r.headers.get("www-authenticate", "")[:70])
r = c.get(f"{BASE}/openapi.json"); paths = list(r.json().get("paths", {}))
chk("openapi-hides-oauth", r.status_code == 200 and not any(p.startswith("/oauth") or "well-known" in p for p in paths), f"{len(paths)} paths")
r = c.post(REG, json={"client_name": "evil", "redirect_uris": ["https://evil.example/cb"]})
chk("dcr-denies-unlisted-host", r.status_code == 400, r.status_code)
r = c.post(REG, json={"client_name": "test-client", "redirect_uris": [f"https://{HOST}/cb"]})
cid = r.json().get("client_id") if r.status_code == 201 else None
chk("dcr-registers", r.status_code == 201 and cid and r.json().get("token_endpoint_auth_method") == "none", cid)
ver = secrets.token_urlsafe(40); chal = b64url(hashlib.sha256(ver.encode()).digest())
RU = f"https://{HOST}/cb"
q = {"response_type": "code", "client_id": "manual", "redirect_uri": RU, "state": "st1", "code_challenge": chal, "code_challenge_method": "S256", "scope": "notes"}
r = c.get(AUTHZ, params={**q, "redirect_uri": "https://evil.example/cb"}); chk("authz-denies-unlisted-host", r.status_code == 400, r.status_code)
r = c.get(AUTHZ, params={**q, "client_id": cid, "redirect_uri": f"https://{HOST}/other"}); chk("authz-denies-unregistered-uri", r.status_code == 400, r.status_code)
r = c.get(AUTHZ, params={k: v for k, v in q.items() if k != "code_challenge"}); chk("authz-no-pkce-bounces", r.status_code == 302 and "error=invalid_request" in r.headers.get("location", ""), r.headers.get("location", "")[:60])
r = c.get(AUTHZ, params=q); chk("authz-page", r.status_code == 200 and 'name="token"' in r.text and HOST in r.text, f"{len(r.text)} bytes")
r = c.post(AUTHZ, data={**q, "token": "nope"}); chk("approve-bad-token-403", r.status_code == 403 and "not one of the agent tokens" in r.text, r.status_code)
if not MINT:
    print(f"RESULT: {P} pass / {F} fail (mint skipped)"); sys.exit(1 if F else 0)
r = c.post(AUTHZ, data={**q, "token": TOK}); loc = r.headers.get("location", "")
qs = parse_qs(urlsplit(loc).query); code = (qs.get("code") or [""])[0]
chk("approve-redirects-with-code", r.status_code == 302 and loc.startswith(RU + "?") and code and qs.get("state") == ["st1"], loc[:50])
r = c.post(TOKEN_EP, data={"grant_type": "authorization_code", "code": code, "redirect_uri": RU, "client_id": "manual", "code_verifier": "wrong" * 10})
chk("token-bad-pkce-400", r.status_code == 400 and r.json().get("error") == "invalid_grant", r.text[:60])
r = c.post(AUTHZ, data={**q, "token": TOK}); code = parse_qs(urlsplit(r.headers["location"]).query)["code"][0]
r = c.post(TOKEN_EP, data={"grant_type": "authorization_code", "code": code, "redirect_uri": RU, "client_id": "manual", "code_verifier": ver})
t = r.json() if r.status_code == 200 else {}
chk("token-issued", r.status_code == 200 and t.get("access_token", "").startswith("nb_") and t.get("refresh_token", "").startswith("nbr_") and r.headers.get("cache-control") == "no-store", f"expires_in={t.get('expires_in')}")
r = c.post(TOKEN_EP, data={"grant_type": "authorization_code", "code": code, "redirect_uri": RU, "client_id": "manual", "code_verifier": ver})
chk("code-single-use", r.status_code == 400, r.status_code)
r = c.get(f"{BASE}/v1/whoami", headers={"Authorization": f"Bearer {t['access_token']}"})
chk("rest-whoami-via-oauth", r.status_code == 200 and (AGENT is None or r.json().get("agent") == AGENT), r.json().get("agent") if r.status_code == 200 else r.status_code)


async def mcp_whoami(tok):
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client
    async with streamablehttp_client(f"{BASE}/mcp", headers={"Authorization": f"Bearer {tok}"}) as (rr, w, _):
        async with ClientSession(rr, w) as s:
            await s.initialize(); res = await s.call_tool("whoami", {})
            return (res.structuredContent or {}).get("result", res.structuredContent) or json.loads(res.content[0].text)


b = asyncio.run(mcp_whoami(t["access_token"]))
chk("mcp-whoami-via-oauth", AGENT is None or b.get("agent") == AGENT, b.get("agent"))
r = c.post(TOKEN_EP, data={"grant_type": "refresh_token", "refresh_token": t["refresh_token"], "client_id": "manual"}); t2 = r.json() if r.status_code == 200 else {}
chk("refresh-rotates", r.status_code == 200 and t2.get("access_token", "").startswith("nb_") and t2.get("refresh_token") != t["refresh_token"])
r = c.post(TOKEN_EP, data={"grant_type": "refresh_token", "refresh_token": t["refresh_token"], "client_id": "manual"}); chk("old-refresh-dead", r.status_code == 400, r.status_code)
r = c.post(REVOKE, data={"token": t2["access_token"]}); chk("revoke-200", r.status_code == 200, r.status_code)
r = c.get(f"{BASE}/v1/whoami", headers={"Authorization": f"Bearer {t2['access_token']}"}); chk("revoked-token-401", r.status_code == 401, r.status_code)
print(f"RESULT: {P} pass / {F} fail"); sys.exit(1 if F else 0)
