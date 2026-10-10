#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VERSION=${1:-dev}
OUT_DIR="$ROOT/dist"
STAGE=$(mktemp -d "${TMPDIR:-/tmp}/wscan-release.XXXXXX")
trap 'python3 -c "import shutil, sys; shutil.rmtree(sys.argv[1], ignore_errors=True)" "$STAGE"' EXIT HUP INT TERM
BUNDLE="$STAGE/wscan-linux-amd64"
LIBRARY_SOURCE=${WSCAN_LIBRARY_SOURCE:-"$ROOT/library"}
test -d "$LIBRARY_SOURCE/nuclei-templates" || { echo "Library required: $LIBRARY_SOURCE" >&2; exit 1; }
mkdir -p "$OUT_DIR"
(cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags="-s -w -X main.version=$VERSION" -o "$BUNDLE/wscan" .)
# Include only runtime checks, indexes and coverage documentation.
mkdir -p "$BUNDLE/library"
for entry in nuclei-templates nmap categories.json products.json MANIFEST.json README.md security; do
  test -e "$LIBRARY_SOURCE/$entry" || continue
  (cd "$LIBRARY_SOURCE" && tar --exclude=.git --exclude=__pycache__ -cf - "$entry") | (cd "$BUNDLE/library" && tar -xf -)
done
# WinPEAS is the explicitly approved optional third-party tool.
mkdir -p "$BUNDLE/tools"
cp -a "$ROOT/tools/winpeas" "$BUNDLE/tools/winpeas"
cp "$ROOT/docs/TRANSFER.md" "$BUNDLE/README-TRANSFER.md"
cp "$ROOT/docs/KNOWN_TEST_FAILURES.md" "$BUNDLE/KNOWN_TEST_FAILURES.md"
cp "$ROOT/docs/ENGINE_POLICY_AUDIT.md" "$BUNDLE/ENGINE_POLICY_AUDIT.md"
cat > "$BUNDLE/start.sh" <<'EOF'
#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
exec ./wscan "$@"
EOF
chmod 755 "$BUNDLE/start.sh" "$BUNDLE/wscan"
ARCHIVE="wscan-$VERSION-linux-amd64.tar.gz"
tar -C "$STAGE" -czf "$OUT_DIR/$ARCHIVE" wscan-linux-amd64
(cd "$OUT_DIR" && sha256sum "$ARCHIVE" > "$ARCHIVE.sha256")
echo "$OUT_DIR/$ARCHIVE"
