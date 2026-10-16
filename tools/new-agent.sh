#!/usr/bin/env bash
# Mint a token for a new agent. The FILE NAME is the agent's identity (audit rows, Inbox/<Agent>/, entry ids).
#   tools/new-agent.sh grok        → ~/.config/notes-bridge/tokens/grok
# Then restart the service (tokens load at start) and hand the token to the agent — or, for connector
# dialogs that run OAuth, paste it on the approval page when the dialog sends you there.
set -euo pipefail
name=${1:?usage: new-agent.sh <agent-name>   (lowercase letters, digits, - or _)}
[[ $name =~ ^[a-z0-9_-]{1,30}$ ]] || { echo "bad name: $name" >&2; exit 2; }
dir=${BRIDGE_TOKEN_DIR:-$HOME/.config/notes-bridge/tokens}
mkdir -p "$dir"; chmod 700 "$dir"
f="$dir/$name"
[[ -e $f ]] && { echo "exists: $f (delete it first to rotate)" >&2; exit 1; }
umask 077; openssl rand -hex 32 > "$f"
echo "agent '$name' → $f"; echo "token: $(cat "$f")"
echo "now: restart notes-bridge, then give this token to the agent (or paste it on the OAuth approval page)."
