#!/usr/bin/env bash
# Build a throwaway vault the test suites can write into. Prints its path.
#   V=$(tests/make-scratch-vault.sh)   then run the server with BRIDGE_VAULT=$V
set -euo pipefail
V=${1:-$(mktemp -d -t notes-bridge-vault.XXXX)}
today=$(date +%F); yday=$(date -d yesterday +%F 2>/dev/null || date -v-1d +%F)
mkdir -p "$V/Daily" "$V/Projects/Garden" "$V/Wiki" "$V/Credentials" "$V/Private"
printf '# %s\n\n- Planted basil on the balcony. Watering schedule: every other day.\n- Called the bank about the card.\n' "$today" > "$V/Daily/$today.md"
printf '# %s\n\n- Weekly review: garden project on track, basil seeds ordered.\n' "$yday" > "$V/Daily/$yday.md"
printf '# Garden\n\nBalcony garden project. Basil, tomatoes, chili. Watering every other day in summer.\n' > "$V/Projects/Garden/README.md"
printf '# Compost\n\nHow the compost bin works. Turn weekly.\n' > "$V/Wiki/Compost.md"
printf '# bank login\n\nuser: me\npassword: hunter2\n' > "$V/Credentials/bank.md"
printf '# Diary\n\nPrivate thoughts.\n' > "$V/Private/diary.md"
echo "$V"
