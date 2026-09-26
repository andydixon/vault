#!/usr/bin/env bash
# Build the vault user guide PDF: docs/guide/vault-guide.pdf
#
#   ./build-pdf.sh
#
# Uses Tectonic (a self-contained XeTeX engine). If `tectonic` is not on PATH,
# a pinned release is downloaded into docs/guide/.tools on first run. LaTeX
# packages and fonts are fetched by Tectonic and cached in your user cache.
# Screenshots are committed in img/; regenerate them with ./shots.py.
set -euo pipefail
cd "$(dirname "$0")"

TECTONIC_VERSION=0.17.0

find_tectonic() {
	if command -v tectonic >/dev/null; then command -v tectonic; return; fi
	local local_bin=.tools/tectonic
	if [[ -x $local_bin ]]; then echo "$local_bin"; return; fi
	local asset
	case "$(uname -s)/$(uname -m)" in
		Linux/x86_64) asset=x86_64-unknown-linux-musl ;;
		Linux/aarch64 | Linux/arm64) asset=aarch64-unknown-linux-musl ;;
		Linux/armv7l) asset=arm-unknown-linux-musleabihf ;;
		Darwin/x86_64) asset=x86_64-apple-darwin ;;
		Darwin/arm64) asset=aarch64-apple-darwin ;;
		*) echo "build-pdf: no Tectonic download for $(uname -s)/$(uname -m); install tectonic and retry" >&2; exit 1 ;;
	esac
	echo "build-pdf: fetching tectonic $TECTONIC_VERSION ($asset)" >&2
	mkdir -p .tools
	curl -fsSL "https://github.com/tectonic-typesetting/tectonic/releases/download/tectonic%40$TECTONIC_VERSION/tectonic-$TECTONIC_VERSION-$asset.tar.gz" |
		tar -xz -C .tools tectonic
	echo "$local_bin"
}

tectonic=$(find_tectonic)

# The cover shows the git version and today's date.
version=$(git describe --tags --always --dirty 2>/dev/null || echo dev)
printf '\\newcommand\\vaultversion{%s}\n\\newcommand\\vaultdate{%s}\n' \
	"$version" "$(date '+%B %Y')" >version.tex

"$tectonic" --keep-logs --chatter minimal vault-guide.tex
echo "build-pdf: wrote $(pwd)/vault-guide.pdf"
