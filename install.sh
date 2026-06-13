#!/bin/bash
# aurscan installer — run with sudo. Builds from source if no binary present.
set -e
cd "$(dirname "$0")"
[ -f aurscan ] || { command -v go >/dev/null || { echo "need go to build"; exit 1; }; \
  CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o aurscan .; }
install -Dm755 aurscan /usr/local/bin/aurscan
ln -sf aurscan /usr/local/bin/syay
ln -sf aurscan /usr/local/bin/aurscan-edit
echo "Installed: aurscan, syay, aurscan-edit -> /usr/local/bin"
echo
if command -v claude >/dev/null; then
  echo "  ✔ Claude Code CLI found — no API key needed (uses your existing login)."
elif [ -n "$ANTHROPIC_API_KEY" ]; then
  echo "  ✔ ANTHROPIC_API_KEY is set."
else
  echo "  ✘ No backend yet: install Claude Code and log in, or export ANTHROPIC_API_KEY."
fi
echo
echo "Pick ONE integration:"
echo "  A) wrapper (recommended), fish:   alias yay=syay; funcsave yay"
echo "  B) in-flow gate, unmodified yay:  yay --save --answeredit All --editor aurscan-edit"
