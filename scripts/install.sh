#!/bin/sh
# Install the host minitcp binary from GitHub Releases into ~/.local/bin.
set -eu

REPO="${MINITCP_REPO:-dfoshidero/minitcp}"
VERSION="${VERSION:-latest}"
DEST_DIR="${MINITCP_BIN:-$HOME/.local/bin}"

os=$(uname -s)
arch=$(uname -m)
case "$os-$arch" in
  Darwin-arm64) asset="minitcp-aarch64-apple-darwin" ;;
  Linux-x86_64) asset="minitcp-x86_64-unknown-linux-gnu" ;;
  Linux-amd64) asset="minitcp-x86_64-unknown-linux-gnu" ;;
  Linux-aarch64) asset="minitcp-aarch64-unknown-linux-gnu" ;;
  Linux-arm64) asset="minitcp-aarch64-unknown-linux-gnu" ;;
  *)
    echo "minitcp: error: no published binary for $os $arch" >&2
    echo "minitcp: supported platforms: macOS arm64; Linux x86_64 and arm64" >&2
    exit 1
    ;;
esac

if [ "$VERSION" = latest ]; then
  url="https://github.com/${REPO}/releases/latest/download/${asset}"
else
  url="https://github.com/${REPO}/releases/download/v${VERSION#v}/${asset}"
fi

if ! mkdir -p "$DEST_DIR"; then
  echo "minitcp: error: cannot create install directory $DEST_DIR" >&2
  exit 1
fi
tmp=$(mktemp "$DEST_DIR/.minitcp.XXXXXX")
trap 'rm -f "$tmp"' EXIT
echo "minitcp: downloading $url"
if ! curl -fsSL --retry 3 --retry-delay 1 --connect-timeout 10 --max-time 120 "$url" -o "$tmp"; then
  echo "minitcp: error: download failed after retries: $url" >&2
  exit 1
fi
chmod +x "$tmp"
if ! "$tmp" --version >/dev/null 2>&1; then
  echo "minitcp: error: downloaded binary will not run on this machine" >&2
  exit 1
fi
mv "$tmp" "$DEST_DIR/minitcp"
trap - EXIT

echo "minitcp: installed $DEST_DIR/minitcp"
case ":$PATH:" in
  *":$DEST_DIR:"*) ;;
  *)
    echo "minitcp: add this to your shell rc:  export PATH=\"$DEST_DIR:\$PATH\""
    ;;
esac
"$DEST_DIR/minitcp" --help
