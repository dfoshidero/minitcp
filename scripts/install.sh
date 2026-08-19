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
  Darwin-x86_64) asset="minitcp-x86_64-apple-darwin" ;;
  Linux-x86_64) asset="minitcp-x86_64-unknown-linux-gnu" ;;
  Linux-amd64) asset="minitcp-x86_64-unknown-linux-gnu" ;;
  Linux-aarch64) asset="minitcp-aarch64-unknown-linux-gnu" ;;
  Linux-arm64) asset="minitcp-aarch64-unknown-linux-gnu" ;;
  *)
    echo "unsupported platform: $os $arch" >&2
    exit 1
    ;;
esac

if [ "$VERSION" = latest ]; then
  url="https://github.com/${REPO}/releases/latest/download/${asset}"
else
  url="https://github.com/${REPO}/releases/download/v${VERSION#v}/${asset}"
fi

mkdir -p "$DEST_DIR"
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
echo "downloading $url"
curl -fsSL "$url" -o "$tmp"
chmod +x "$tmp"
mv "$tmp" "$DEST_DIR/minitcp"
trap - EXIT

echo "installed $DEST_DIR/minitcp"
case ":$PATH:" in
  *":$DEST_DIR:"*) ;;
  *)
    echo "add this to your shell rc:  export PATH=\"$DEST_DIR:\$PATH\""
    ;;
esac
"$DEST_DIR/minitcp" --help
