#!/bin/sh
set -eu

WORKSPACE="${PACT_SANDBOX_WORKDIR:-/workspace}"
REAL_NPM="$(command -v npm)"

rm -rf "$WORKSPACE"
mkdir -p "$WORKSPACE"
cp -a /app/. "$WORKSPACE"/

mkdir -p "$WORKSPACE/bin"
cat > "$WORKSPACE/bin/npm" <<'EOF'
#!/bin/sh
exec node /app/src/cli.js npm "$@"
EOF
chmod +x "$WORKSPACE/bin/npm"

export PACT_REAL_NPM="$REAL_NPM"
export PATH="$WORKSPACE/bin:$PATH"

cd "$WORKSPACE"

if [ "$#" -gt 0 ]; then
  exec "$@"
fi

exec sh