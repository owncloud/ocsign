#!/usr/bin/env bash
# gen_golden.sh — independent oracle for the canonicalization golden vectors.
#
# This deliberately does NOT use the Go implementation. It re-derives the
# canonical manifest bytes M and the per-file hash map from the shared rules in
# spec §3, using coreutils, so the committed golden files are an independent
# check on internal/manifest rather than a snapshot of its own output.
#
# Limitation: this generator only handles filenames that need no JSON escaping
# (no '"', '\', or control bytes). All committed fixture trees satisfy that; if a
# future fixture needs escaping, extend this script and the Go serializer both.
#
# The golden files are written to testdata/golden/<tree-name>/ — a sibling of the
# fixture trees, never inside a tree, so Build() does not hash them as tree files.
#
# Usage: testdata/gen_golden.sh <tree-dir>
#   writes testdata/golden/<name>/hashes.expected.json (pretty, sorted SHA-512 hex)
#     and testdata/golden/<name>/manifest.canonical.json (compact canonical bytes
#         M, no trailing newline)
set -euo pipefail

tree="${1:?usage: gen_golden.sh <tree-dir>}"
tree="${tree%/}"
out="$(dirname "$tree")/golden/$(basename "$tree")"
mkdir -p "$out"

# App-mode exclusions (spec §3.2), matched by base filename.
is_excluded() {
	local rel="$1" base
	base="$(basename "$rel")"
	case "$rel" in
	appinfo/signature.json) return 0 ;;
	esac
	case "$base" in
	.DS_Store | Thumbs.db | .directory | .webapp) return 0 ;;
	esac
	case "$base" in
	.webapp-owncloud-*) return 0 ;;
	esac
	return 1
}

# Collect (key, hash) pairs into a byte-sorted list.
pairs=()
while IFS= read -r -d '' f; do
	rel="${f#"$tree"/}"
	if is_excluded "$rel"; then
		continue
	fi
	h="$(sha512sum "$f" | cut -d' ' -f1)"
	pairs+=("$rel"$'\t'"$h")
done < <(find "$tree" -type f -print0)

# Byte-wise ascending sort on the key (LC_ALL=C), tab-separated.
sorted="$(printf '%s\n' "${pairs[@]}" | LC_ALL=C sort)"

# Compact canonical bytes M: {"k":"v",...} no whitespace, no trailing newline.
{
	printf '{'
	first=1
	while IFS=$'\t' read -r key hash; do
		[ -z "$key" ] && continue
		if [ "$first" -eq 0 ]; then printf ','; fi
		first=0
		printf '"%s":"%s"' "$key" "$hash"
	done <<<"$sorted"
	printf '}'
} >"$out/manifest.canonical.json"

# Pretty per-file map for human inspection (same sorted order, 2-space indent).
{
	printf '{\n'
	n="$(printf '%s\n' "$sorted" | grep -c . || true)"
	i=0
	while IFS=$'\t' read -r key hash; do
		[ -z "$key" ] && continue
		i=$((i + 1))
		if [ "$i" -lt "$n" ]; then sep=','; else sep=''; fi
		printf '  "%s": "%s"%s\n' "$key" "$hash" "$sep"
	done <<<"$sorted"
	printf '}\n'
} >"$out/hashes.expected.json"

echo "wrote $out/manifest.canonical.json ($(wc -c <"$out/manifest.canonical.json") bytes)"
echo "wrote $out/hashes.expected.json"
