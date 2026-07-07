#!/usr/bin/env bash
# build-release.sh — cross-compile ocsign for all supported OS/arch targets and
# produce checksummed archives (spec §7: single static binary, linux/darwin/
# windows on amd64/arm64).
#
# Usage: scripts/build-release.sh <version> [out-dir]
#   <version> is embedded via -ldflags and used in archive names, e.g. v0.1.0.
#   [out-dir]  defaults to ./dist.
set -euo pipefail

version="${1:?usage: build-release.sh <version> [out-dir]}"
outdir="${2:-dist}"
pkg="github.com/DeepDiver1975/ocsign/internal/version"

rm -rf "$outdir"
mkdir -p "$outdir"
# Absolute so archive creation works regardless of the staging cwd.
outdir="$(cd "$outdir" && pwd)"

targets=(
	"linux/amd64"
	"linux/arm64"
	"darwin/amd64"
	"darwin/arm64"
	"windows/amd64"
	"windows/arm64"
)

for target in "${targets[@]}"; do
	goos="${target%/*}"
	goarch="${target#*/}"

	bin="ocsign"
	[ "$goos" = "windows" ] && bin="ocsign.exe"

	stage="$(mktemp -d)"
	echo "building $goos/$goarch ..."
	CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
		go build -trimpath \
		-ldflags "-s -w -X ${pkg}.Version=${version}" \
		-o "$stage/$bin" ./cmd/ocsign

	cp LICENSE README.md "$stage/"

	base="ocsign_${version}_${goos}_${goarch}"
	if [ "$goos" = "windows" ]; then
		(cd "$stage" && zip -q -r "$outdir/${base}.zip" .)
	else
		tar -czf "$outdir/${base}.tar.gz" -C "$stage" .
	fi
	rm -rf "$stage"
done

# One checksums file covering every archive.
(cd "$outdir" && sha256sum ./* >"SHA256SUMS")
echo "artifacts in $outdir:"
ls -1 "$outdir"
