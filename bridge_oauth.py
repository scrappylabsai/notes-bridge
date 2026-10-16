#!/usr/bin/env python3
"""bridge_oauth.py — the smallest OAuth 2.1 authorization server that satisfies MCP connector dialogs.

Why it exists: Grok's custom-connector dialog (ChatGPT's and Claude's too) will not take a bearer
token. On a 401 from /mcp it asks for an OAuth client + endpoints and then drives the browser
through authorization-code + PKCE. This module is that flow and nothing more:

  GET  /.well-known/oauth-protected-resource[/mcp]  RFC 9728 — which authorization server guards /mcp
  GET  /.well-known/oauth-authorization-server      RFC 8414 — our endpoints and capabilities
  POST /oauth/register                              RFC 7591 — dynamic client registration (public clients)
  GET  /oauth/authorize                             approval page: the owner pastes an AGENT token
  POST /oauth/authorize                             checks it, mints a one-shot code, redirects back
  POST /oauth/token                                 code (+PKCE S256) or refresh_token → access token
  POST /oauth/revoke                                RFC 7009

Identity: the approval page asks for one of the per-agent tokens in BRIDGE_TOKEN_DIR/.
The minted access token inherits THAT agent, so the audit log, Inbox/<Agent>/ and every entry id
still say "grok" — OAuth is a wrapper around the same identity, not a new one.

Storage: access/refresh tokens are opaque (nb_… / nbr_…), kept HASHED in <STATE>/oauth.json with
agent, client, scope, expiry. Delete a row (or the file) to revoke. Authorization codes live in
memory for 5 minutes and burn on first use.

Guard rails: PKCE S256 is mandatory; the redirect host must be in policy.json `oauth_redirect_hosts`
(suffix match) or http://localhost — deny wins even for registered clients; a wrong token on the
approval page costs a 1 s sleep and counts against the anonymous rate bucket.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import threading
import time
from string import Template
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

ACCESS_TTL = 30 * 86400      # 30 days; clients refresh after that
REFRESH_TTL = 180 * 86400    # 180 days; then the owner approves again
CODE_TTL = 300
MAX_CLIENTS = 50
NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def _h(tok: str) -> str:
    return hashlib.sha256(tok.encode()).hexdigest()


def _now() -> int:
    return int(time.time())


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class OAuthStore:
    """Hashed tokens + registered clients on disk; codes in memory."""

    def __init__(self, path: Path):
        self.path = path
        self.lock = threading.Lock()
        self.data: dict = {"clients": {}, "tokens": {}}
        if path.is_file():
            try:
                self.data = json.loads(path.read_text())
            except ValueError:
                pass
        self.data.setdefault("clients", {})
        self.data.setdefault("tokens", {})
        self.codes: dict[str, dict] = {}

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, indent=1))
        os.chmod(tmp, 0o600)
        tmp.replace(self.path)

    def _gc(self) -> None:
        now = _now()
        self.data["tokens"] = {k: v for k, v in self.data["tokens"].items() if v["exp"] > now}

    # ── tokens ──
    def agent_for(self, tok: str) -> Optional[str]:
        if not tok.startswith("nb_"):
            return None
        row = self.data["tokens"].get(_h(tok))
        if not row or row["kind"] != "access" or row["exp"] < _now():
            return None
        return row["agent"]

    def mint(self, agent: str, client_id: str, scope: str) -> dict:
        acc, ref = "nb_" + secrets.token_urlsafe(32), "nbr_" + secrets.token_urlsafe(32)
        now = _now()
        with self.lock:
            self.data["tokens"][_h(acc)] = {"kind": "access", "agent": agent, "client_id": client_id,
                                            "scope": scope, "iat": now, "exp": now + ACCESS_TTL}
            self.data["tokens"][_h(ref)] = {"kind": "refresh", "agent": agent, "client_id": client_id,
                                            "scope": scope, "iat": now, "exp": now + REFRESH_TTL}
            self._gc()
            self._save()
        return {"access_token": acc, "token_type": "Bearer", "expires_in": ACCESS_TTL,
                "refresh_token": ref, "scope": scope}

    def pop_refresh(self, tok: str, client_id: str) -> Optional[dict]:
        with self.lock:
            row = self.data["tokens"].get(_h(tok))
            if not row or row["kind"] != "refresh" or row["exp"] < _now() or row["client_id"] != client_id:
                return None
            del self.data["tokens"][_h(tok)]
            self._save()
            return row

    def revoke(self, tok: str) -> bool:
        with self.lock:
            gone = self.data["tokens"].pop(_h(tok), None) is not None
            if gone:
                self._save()
            return gone

    def live(self) -> list[dict]:
        now = _now()
        return [{"agent": v["agent"], "client_id": v["client_id"], "kind": v["kind"], "exp": v["exp"]}
                for v in self.data["tokens"].values() if v["exp"] > now]

    # ── clients ──
    def register(self, name: str, redirect_uris: list[str]) -> dict:
        with self.lock:
            if len(self.data["clients"]) >= MAX_CLIENTS:
                oldest = min(self.data["clients"], key=lambda k: self.data["clients"][k]["iat"])
                del self.data["clients"][oldest]
            cid = "c_" + secrets.token_urlsafe(12)
            self.data["clients"][cid] = {"name": name[:80], "redirect_uris": redirect_uris[:10], "iat": _now()}
            self._save()
        return {"client_id": cid, **self.data["clients"][cid]}

    def client(self, cid: str) -> Optional[dict]:
        return self.data["clients"].get(cid)

    # ── codes ──
    def new_code(self, **fields) -> str:
        code = secrets.token_urlsafe(32)
        now = _now()
        self.codes = {k: v for k, v in self.codes.items() if v["exp"] > now}
        self.codes[code] = {**fields, "exp": now + CODE_TTL}
        return code

    def pop_code(self, code: str) -> Optional[dict]:
        row = self.codes.pop(code, None)
        return row if row and row["exp"] > _now() else None


def host_ok(uri: str, allowed: list[str]) -> bool:
    u = urlsplit(uri)
    if u.fragment or not u.hostname:
        return False
    h = u.hostname.lower()
    if u.scheme == "http" and h in ("localhost", "127.0.0.1"):
        return True
    if u.scheme != "https":
        return False
    return any(h == a or h.endswith("." + a) for a in (x.lower() for x in allowed))


async def _form(request: Request) -> dict[str, str]:
    body = (await request.body()).decode(errors="replace")
    if "json" in (request.headers.get("content-type") or ""):
        try:
            d = json.loads(body or "{}")
            return {k: str(v) for k, v in d.items()} if isinstance(d, dict) else {}
        except ValueError:
            return {}
    return dict(parse_qsl(body, keep_blank_values=True))


PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Approve connector — $resource_name</title>
<style>
:root{color-scheme:light dark;--bg:#ffffff;--fg:#1a1a1f;--muted:#4d4d5c;--line:#6e6e82;--accent:#2a5bd7;--err:#b3261e}
@media (prefers-color-scheme:dark){:root{--bg:#121216;--fg:#f2f2f5;--muted:#c3c3cf;--line:#8a8aa0;--accent:#8fb0ff;--err:#ffb4ab}}
body{margin:0;padding:24px 16px;background:var(--bg);color:var(--fg);font:16px/1.5 system-ui,sans-serif}
main{max-width:520px;margin:0 auto}h1{font-size:1.35rem;margin:0 0 12px}p{margin:0 0 12px}.m{color:var(--muted)}
dl{display:grid;grid-template-columns:auto 1fr;gap:4px 12px;margin:0 0 16px}dt{color:var(--muted)}dd{margin:0;word-break:break-all}
label{display:block;margin:0 0 6px;font-weight:600}input{width:100%;box-sizing:border-box;padding:10px;font:inherit;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg)}
input:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
button{margin-top:14px;padding:10px 18px;font:inherit;font-weight:600;border:0;border-radius:6px;background:var(--accent);color:#fff;cursor:pointer}
@media (prefers-color-scheme:dark){button{color:#0b1a3d}}button:focus-visible{outline:3px solid var(--fg);outline-offset:2px}
.err{color:var(--err);font-weight:600}
</style></head><body><main>
<h1>Approve a connector</h1>
<p><strong>$client</strong> wants to use <strong>$resource_name</strong> as one of $owner's agents.
After approval it is sent back to <strong>$rhost</strong>.</p>
<dl><dt>Client</dt><dd>$client_id</dd><dt>Scope</dt><dd>$scope</dd><dt>Return to</dt><dd>$redirect_uri</dd></dl>
$error
<form method="post" action="$action" autocomplete="off">
$hidden
<label for="tok">Agent token</label>
<p class="m" id="tokhelp">The token from <code>BRIDGE_TOKEN_DIR/&lt;agent&gt;</code>. The connector becomes that agent.</p>
<input id="tok" name="token" type="password" required aria-describedby="tokhelp" autofocus>
<button type="submit">Approve</button>
</form>
<p class="m">Nothing else to do here. Close this page if you did not start this.</p>
</main></body></html>"""

ERR_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} — notes-bridge</title><style>body{{margin:0;padding:24px 16px;font:16px/1.5 system-ui,sans-serif;background:#fff;color:#1a1a1f}}
@media (prefers-color-scheme:dark){{body{{background:#121216;color:#f2f2f5}}}}main{{max-width:520px;margin:0 auto}}</style></head>
<body><main><h1>{title}</h1><p>{msg}</p></main></body></html>"""


def build_router(*, issuer: str, resource: str, resource_name: str, owner: str, store: OAuthStore,
                 agent_tokens: dict[str, str], allowed_hosts: list[str],
                 audit: Callable[[dict], None]) -> APIRouter:
    """issuer = https://bridge.example.com; resource = https://bridge.example.com/mcp;
    agent_tokens = {token: agent} (the static per-agent files)."""
    r = APIRouter(include_in_schema=False)   # keep these out of the REST OpenAPI Muse builds from
    authz, token_ep = f"{issuer}/oauth/authorize", f"{issuer}/oauth/token"

    def as_meta() -> dict:
        return {
            "issuer": issuer,
            "authorization_endpoint": authz,
            "token_endpoint": token_ep,
            "registration_endpoint": f"{issuer}/oauth/register",
            "revocation_endpoint": f"{issuer}/oauth/revoke",
            "response_types_supported": ["code"],
            "response_modes_supported": ["query"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "revocation_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": ["notes"],
            "service_documentation": f"{issuer}/docs",
        }

    def pr_meta() -> dict:
        return {"resource": resource, "resource_name": resource_name, "authorization_servers": [issuer],
                "bearer_methods_supported": ["header"], "scopes_supported": ["notes"]}

    @r.get("/.well-known/oauth-protected-resource")
    @r.get("/.well-known/oauth-protected-resource/mcp")
    def protected_resource():
        return JSONResponse(pr_meta(), headers=NO_STORE)

    @r.get("/.well-known/oauth-authorization-server")
    @r.get("/.well-known/oauth-authorization-server/mcp")
    def auth_server():
        return JSONResponse(as_meta(), headers=NO_STORE)

    @r.post("/oauth/register", status_code=201)
    async def register(request: Request):
        try:
            d = json.loads((await request.body()).decode() or "{}")
        except ValueError:
            d = None
        if not isinstance(d, dict):
            return JSONResponse({"error": "invalid_client_metadata", "error_description": "JSON body required"}, 400)
        uris = d.get("redirect_uris") or []
        if not isinstance(uris, list) or not uris or not all(isinstance(u, str) and host_ok(u, allowed_hosts) for u in uris):
            return JSONResponse({"error": "invalid_redirect_uri",
                                 "error_description": "redirect_uris must be https on an allowed host (or http://localhost)"}, 400)
        c = store.register(str(d.get("client_name") or "unnamed"), uris)
        audit({"agent": None, "m": "OAUTH", "p": "register", "q": f"{c['client_id']} {c['name']} {uris[0]}"[:120], "s": 201, "ms": 0})
        return JSONResponse({"client_id": c["client_id"], "client_name": c["name"], "redirect_uris": c["redirect_uris"],
                             "client_id_issued_at": c["iat"], "token_endpoint_auth_method": "none",
                             "grant_types": ["authorization_code", "refresh_token"], "response_types": ["code"]},
                            201, headers=NO_STORE)

    def _check_authz(q: dict) -> tuple[Optional[str], Optional[str]]:
        """→ (fatal_error_message, redirectable_error). fatal = no safe redirect target."""
        ru, cid = q.get("redirect_uri", ""), q.get("client_id", "")
        if not cid:
            return "client_id is missing", None
        if not ru or not host_ok(ru, allowed_hosts):
            return f"redirect host not allowed: {html.escape(urlsplit(ru).hostname or ru or '(none)')} — add it to policy.json oauth_redirect_hosts", None
        c = store.client(cid)
        if c and ru not in c["redirect_uris"]:
            return "redirect_uri is not one this client registered", None
        if q.get("response_type") != "code":
            return None, "unsupported_response_type"
        if not q.get("code_challenge") or q.get("code_challenge_method", "S256") != "S256":
            return None, "invalid_request"
        return None, None

    def _render(q: dict, error: str = "") -> HTMLResponse:
        c = store.client(q["client_id"])
        hidden = "\n".join(f'<input type="hidden" name="{k}" value="{html.escape(q.get(k, ""))}">'
                           for k in ("client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method", "scope", "resource"))
        page = Template(PAGE).substitute(owner=html.escape(owner), client=html.escape(c["name"] if c else q["client_id"]), client_id=html.escape(q["client_id"]),
                           resource_name=html.escape(resource_name), rhost=html.escape(urlsplit(q["redirect_uri"]).hostname or ""),
                           redirect_uri=html.escape(q["redirect_uri"]), scope=html.escape(q.get("scope") or "notes"),
                           action=html.escape(authz), hidden=hidden,
                           error=f'<p class="err" role="alert">{html.escape(error)}</p>' if error else "")
        return HTMLResponse(page, status_code=403 if error else 200, headers=NO_STORE)

    def _bounce(q: dict, err: str) -> RedirectResponse:
        sep = "&" if "?" in q["redirect_uri"] else "?"
        params = {"error": err, **({"state": q["state"]} if q.get("state") else {})}
        return RedirectResponse(f"{q['redirect_uri']}{sep}{urlencode(params)}", status_code=302, headers=NO_STORE)

    @r.get("/oauth/authorize")
    def authorize_page(request: Request):
        q = dict(request.query_params)
        fatal, err = _check_authz(q)
        if fatal:
            return HTMLResponse(ERR_PAGE.format(title="Cannot approve", msg=fatal), status_code=400, headers=NO_STORE)
        if err:
            return _bounce(q, err)
        return _render(q)

    @r.post("/oauth/authorize")
    async def authorize_submit(request: Request):
        q = await _form(request)
        q.setdefault("response_type", "code")
        fatal, err = _check_authz(q)
        if fatal:
            return HTMLResponse(ERR_PAGE.format(title="Cannot approve", msg=fatal), status_code=400, headers=NO_STORE)
        if err:
            return _bounce(q, err)
        tok = (q.get("token") or "").strip()
        agent = next((a for t, a in agent_tokens.items() if hmac.compare_digest(tok, t)), None)
        if not agent:
            time.sleep(1)
            audit({"agent": None, "m": "OAUTH", "p": "approve", "q": f"{q['client_id']} bad-token", "s": 403, "ms": 0})
            return _render(q, "That token is not one of the agent tokens. Nothing was approved.")
        code = store.new_code(agent=agent, client_id=q["client_id"], redirect_uri=q["redirect_uri"],
                              code_challenge=q["code_challenge"], scope=q.get("scope") or "notes")
        audit({"agent": agent, "m": "OAUTH", "p": "approve", "q": f"{q['client_id']} → {urlsplit(q['redirect_uri']).hostname}", "s": 302, "ms": 0})
        sep = "&" if "?" in q["redirect_uri"] else "?"
        params = {"code": code, **({"state": q["state"]} if q.get("state") else {})}
        return RedirectResponse(f"{q['redirect_uri']}{sep}{urlencode(params)}", status_code=302, headers=NO_STORE)

    def _err(code: str, desc: str, status: int = 400) -> JSONResponse:
        return JSONResponse({"error": code, "error_description": desc}, status, headers=NO_STORE)

    @r.post("/oauth/token")
    async def token(request: Request):
        f = await _form(request)
        grant, cid = f.get("grant_type"), f.get("client_id", "")
        if grant == "authorization_code":
            row = store.pop_code(f.get("code", ""))
            if not row:
                return _err("invalid_grant", "code unknown, expired or already used")
            if not cid:
                cid = row["client_id"]   # some clients omit client_id for public clients
            if row["client_id"] != cid or row["redirect_uri"] != f.get("redirect_uri", row["redirect_uri"]):
                return _err("invalid_grant", "client_id/redirect_uri do not match the code")
            ver = f.get("code_verifier", "")
            if not ver or not hmac.compare_digest(_b64url(hashlib.sha256(ver.encode()).digest()), row["code_challenge"]):
                return _err("invalid_grant", "PKCE verification failed")
            out = store.mint(row["agent"], cid, row["scope"])
            audit({"agent": row["agent"], "m": "OAUTH", "p": "mint", "q": cid, "s": 200, "ms": 0})
            return JSONResponse(out, headers=NO_STORE)
        if grant == "refresh_token":
            rt = f.get("refresh_token", "")
            if not cid:
                probe = store.data["tokens"].get(_h(rt))
                cid = probe["client_id"] if probe else ""
            row = store.pop_refresh(rt, cid)
            if not row:
                return _err("invalid_grant", "refresh token unknown, expired or wrong client")
            out = store.mint(row["agent"], cid, row["scope"])
            audit({"agent": row["agent"], "m": "OAUTH", "p": "refresh", "q": cid, "s": 200, "ms": 0})
            return JSONResponse(out, headers=NO_STORE)
        return _err("unsupported_grant_type", "use authorization_code or refresh_token")

    @r.post("/oauth/revoke")
    async def revoke(request: Request):
        f = await _form(request)
        if store.revoke(f.get("token", "")):
            audit({"agent": None, "m": "OAUTH", "p": "revoke", "q": "", "s": 200, "ms": 0})
        return JSONResponse({}, headers=NO_STORE)   # RFC 7009: 200 even for unknown tokens

    return r
