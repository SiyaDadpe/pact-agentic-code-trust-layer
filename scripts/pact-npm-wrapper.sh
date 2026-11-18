#!/bin/sh
set -eu

REAL_NPM="${PACT_REAL_NPM:-}"
PACT_CLI="${PACT_CLI:-}"

if [ -z "$REAL_NPM" ]; then
  echo "PACT_REAL_NPM is not configured; refusing to run npm through the wrapper." >&2
  exit 1
fi

if [ -z "$PACT_CLI" ]; then
  echo "PACT_CLI is not configured; refusing to run npm through the wrapper." >&2
  exit 1
fi

case "${1:-}" in
  install|i|ci)
    exec node "$PACT_CLI" npm "$@"
    ;;
  *)
    exec "$REAL_NPM" "$@"
    ;;
esac