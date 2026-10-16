# notes-bridge

**One door that lets your cloud agents into your local notes, on your terms.**

You keep a folder of Markdown notes (Obsidian, Logseq, plain files) that is your *local brain*. You also use
several hosted assistants: Claude (claude.ai, the phone app, Claude Desktop), Grok (grok.com and the app),
Meta Muse, ChatGPT. Each of them can take a "custom connector". This is the one small server you point them
all at, so every one of them can search your notes, read them, and leave you things in an inbox, while you
keep every rule in one place:

- **one token per agent** — the file name is the agent's identity; it lands in the audit log, the inbox folder and every entry it writes
- **a read policy** — allow-listed folders, deny wins, no path tricks
- **append-only writes** — an inbox per agent and ledgers (money, time, counts); nothing is ever edited or deleted
- **untrusted by construction** — everything an agent writes carries a banner and can be judged by a scanner before you read it
- **one audit line per request** — who, what, when, status; no content
- **three doors on one service** — REST + OpenAPI (`/v1`), MCP (`/mcp`), and the OAuth handshake the connector dialogs insist on

It is ~900 lines of Python (FastAPI + the official MCP SDK), one `policy.json`, and a tunnel.
No database, no accounts, no framework. Read [PLAYBOOK.md](PLAYBOOK.md) for the pattern and the lessons;
this file is the quickstart.

Built with [Claude Code](https://claude.com/claude-code) and released by [ScrappyLabs](https://scrappylabs.ai). MIT.

## Quickstart (about 15 minutes)

```bash
git clone https://github.com/scrappylabsai/notes-bridge ~/notes-bridge && cd ~/notes-bridge
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp policy.example.json policy.json            # edit: which folders agents may read, where OAuth may redirect
tools/new-agent.sh claude                     # one token file per agent; repeat per vendor (grok, muse, chatgpt…)

export BRIDGE_OWNER="Your Name" BRIDGE_VAULT=~/notes BRIDGE_PUBLIC_URL=https://bridge.example.com
.venv/bin/python server.py                    # listens on 127.0.0.1:9740 only
```

Then give it a public https hostname with any tunnel. With Cloudflare:

```bash
cloudflared tunnel create notes-bridge
cloudflared tunnel --config /dev/null route dns notes-bridge bridge.example.com
cp deploy/cloudflared.example.yml ~/.cloudflared/notes-bridge.yml   # fill in the tunnel id
cloudflared tunnel --config ~/.cloudflared/notes-bridge.yml run
```

`curl https://bridge.example.com/health` should answer `{"ok": true, …}`. To keep it running, use
`deploy/notes-bridge.service` (systemd user unit) and the equivalent for `cloudflared`.

## Connect an agent

| Agent | Where | What to enter | Auth step |
|---|---|---|---|
| **Claude** (claude.ai web, phone app, Claude Desktop) | Settings → Customize → Connectors → Add connector → *Add custom connector* | name + `https://bridge.example.com/mcp` (step 2 empty) → Connect | the dialog finds the OAuth door itself; our approval page opens; paste that agent's token |
| **Grok** (grok.com) | grok.com/connectors → New Connector → *Custom* | name + the same URL → it then asks for OAuth fields: Client ID `grok`, secret blank, Authorization Endpoint `…/oauth/authorize`, Token Endpoint `…/oauth/token`, Scopes `notes`, "none (PKCE only)" → Save & Connect | approval page, paste the token |
| **Grok** (phone app) | Settings → Connectors → add custom | name + URL only | it self-discovers (no fields); approval page on the phone |
| **ChatGPT** | Settings → Connectors → Create | name + URL, auth "OAuth" | same self-discovery path (expected; not yet exercised by us) |
| **Meta Muse** | custom connector from an OpenAPI document | `https://bridge.example.com/openapi.json` + the token as a bearer/API key | no OAuth needed |
| **Claude Code** | `claude mcp add --transport http -s user notes https://bridge.example.com/mcp` | then `/mcp` → Authenticate (OAuth, localhost callback) | or `--header "Authorization: Bearer <token>"` to skip OAuth |
| **xAI API** | `tools:[{"type":"mcp","server_url":"https://bridge.example.com/mcp","authorization":"<token>"}]` | | static token |

The first message to send any of them: *"Call whoami on my notes connector, then search my notes for X and
read the best match."* Then look at `~/.local/state/notes-bridge/access.jsonl` — you will see the agent's
name on every row.

## The tools (same nine over REST and MCP)

| Tool | REST | What it does |
|---|---|---|
| `whoami` | `GET /v1/whoami` | which agent you are, what you may read/write |
| `search_notes` | `GET /v1/notes/search?q=&k=` | search → paths + snippets (policy-filtered) |
| `read_note` | `GET /v1/notes/read?path=` | one `.md` note, capped at `max_read_bytes` |
| `daily_note` | `GET /v1/notes/daily?date=` | a day's log (`Daily/YYYY-MM-DD.md`) |
| `list_notes` | `GET /v1/notes/list?dir=&limit=` | newest-first listing of a folder |
| `add_inbox_note` | `POST /v1/notes/inbox` | append to `Inbox/<Agent>/<agent>-inbox-<date>.md`; the day's log gets a pointer |
| `list_ledgers` / `read_ledger` | `GET /v1/ledgers[/{name}]` | ledgers are Markdown bullet lists |
| `add_ledger_entry` | `POST /v1/ledgers/{name}/entries` | append one line; a ledger is created on first write |

## Configuration (environment)

| Variable | Default | Meaning |
|---|---|---|
| `BRIDGE_OWNER` | `the owner` | your name, shown to agents and on the approval page |
| `BRIDGE_NAME` | `Notes Bridge` | service title (the connector's name) |
| `BRIDGE_VAULT` | `~/notes` | the notes folder |
| `BRIDGE_PUBLIC_URL` | `https://bridge.example.com` | the public base; also the OAuth issuer |
| `BRIDGE_TOKEN_DIR` | `~/.config/notes-bridge/tokens` | one file per agent |
| `BRIDGE_STATE` | `~/.local/state/notes-bridge` | `access.jsonl` (audit) and `oauth.json` (minted tokens, hashed) |
| `BRIDGE_POLICY` | `./policy.json` | read allow/deny, limits, allowed OAuth redirect hosts |
| `BRIDGE_SEARCH_URL` | *(unset)* | optional indexer: `POST {url}/search {"query","k"}` → hits with `path`/`file_path`, `content`/`text`, optional `heading_path`, `score`. Unset = built-in term-match search over the vault (fine to a few thousand notes) |
| `BRIDGE_SCAN_CMD` | *(unset)* | optional injection judge: a command that reads the entry on stdin and prints a verdict (JSON with `verdict`, or a last line). Unset = entries are marked `UNGATED` so you can see they were not judged |
| `BRIDGE_DAILY_DIR` / `BRIDGE_INBOX_DIR` / `BRIDGE_LEDGER_DIR` | `Daily` / `Inbox` / `Ledgers` | folder names inside the vault |
| `BRIDGE_PORT` | `9740` | loopback port |

## Tests

Three suites, each a single file. Writes go to a **scratch vault**, never the real one:

```bash
V=$(tests/make-scratch-vault.sh)
BRIDGE_VAULT=$V BRIDGE_TOKEN_DIR=/tmp/tok BRIDGE_STATE=/tmp/state BRIDGE_PORT=9741 BRIDGE_POLICY=policy.example.json \
  BRIDGE_PUBLIC_URL=https://bridge.example.com .venv/bin/python server.py &      # after tools/new-agent.sh with BRIDGE_TOKEN_DIR=/tmp/tok

B=http://127.0.0.1:9741 T=$(cat /tmp/tok/claude) VAULT=$V WRITES=1 tests/rest-test.sh          # REST door
.venv/bin/python tests/mcp-test.py http://127.0.0.1:9741/mcp $(cat /tmp/tok/claude) 1 claude    # MCP door
.venv/bin/python tests/oauth-test.py http://127.0.0.1:9741 $(cat /tmp/tok/claude) claude 1     # OAuth door
```

Against the public URL run the same with `WRITES=0` / `0` / `mint=0`: reads and discovery only.

## Revoking and rotating

- Static token: delete or overwrite `tokens/<agent>`, restart. That agent's connector stops at the next call.
- OAuth-minted tokens (`nb_…`): they live hashed in `BRIDGE_STATE/oauth.json`. Delete the agent's rows (or the file) and restart. The static token is only the *approval* secret; rotating it does not revoke tokens already minted — delete the rows too.
- Everything else is a Markdown file in your vault: inboxes and ledgers are yours to edit, move or delete.
