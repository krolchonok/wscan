#!/bin/sh
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VERSION=${1:-dev}
OUT_DIR="$ROOT/dist"
STAGE=$(mktemp -d "${TMPDIR:-/tmp}/wscan-release.XXXXXX")
trap 'python3 -c "import shutil, sys; shutil.rmtree(sys.argv[1], ignore_errors=True)" "$STAGE"' EXIT HUP INT TERM
BUNDLE="$STAGE/wscan-linux-amd64"
LIBRARY_SOURCE=${WSCAN_LIBRARY_SOURCE:-"$ROOT/library"}
NUCLEI_SOURCE=${WSCAN_NUCLEI_SOURCE:-"$ROOT/bin/nuclei"}
test -x "$NUCLEI_SOURCE" || { echo "Nuclei Linux amd64 required: $NUCLEI_SOURCE" >&2; exit 1; }
test -d "$LIBRARY_SOURCE/nuclei-templates" || { echo "Library required: $LIBRARY_SOURCE" >&2; exit 1; }
mkdir -p "$BUNDLE/bin" "$OUT_DIR"
(cd "$ROOT" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags="-s -w -X main.version=$VERSION" -o "$BUNDLE/wscan" .)
cp "$NUCLEI_SOURCE" "$BUNDLE/bin/nuclei"
cp "$ROOT/bin/nuclei.LICENSE.md" "$ROOT/bin/README.md" "$BUNDLE/bin/"
# Copy runtime library without Git history or Python caches.
(cd "$LIBRARY_SOURCE" && tar --exclude=.git --exclude=__pycache__ -cf - .) | (mkdir -p "$BUNDLE/library" && cd "$BUNDLE/library" && tar -xf -)
cp -a "$ROOT/tools" "$BUNDLE/tools"
cp "$ROOT/docs/TRANSFER.md" "$BUNDLE/README-TRANSFER.md"
cp "$ROOT/docs/KNOWN_TEST_FAILURES.md" "$BUNDLE/KNOWN_TEST_FAILURES.md"
cat > "$BUNDLE/start.sh" <<'EOF'
#!/bin/sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
if ! command -v nmap >/dev/null 2>&1; then
  echo "Nmap отсутствует: полный набор NSE требует Nmap в PATH." >&2
fi
exec ./wscan "$@"
EOF
chmod 755 "$BUNDLE/start.sh" "$BUNDLE/wscan" "$BUNDLE/bin/nuclei"
ARCHIVE="wscan-$VERSION-linux-amd64.tar.gz"
tar -C "$STAGE" -czf "$OUT_DIR/$ARCHIVE" wscan-linux-amd64
(cd "$OUT_DIR" && sha256sum "$ARCHIVE" > "$ARCHIVE.sha256")
echo "$OUT_DIR/$ARCHIVE"
