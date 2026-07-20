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
# Usage: testdata/gen_golden.sh [--mode app|core] <tree-dir>
#   writes testdata/golden/<name>/hashes.expected.json (pretty, sorted SHA-512 hex)
#     and testdata/golden/<name>/manifest.canonical.json (compact canonical bytes
#         M, no trailing newline)
#   --mode core applies the core-mode exclusions (§3.6) and the root .htaccess
#     marker normalization; default is app mode (§3.2).
set -euo pipefail

mode="app"
if [ "${1:-}" = "--mode" ]; then
	mode="${2:?usage: gen_golden.sh [--mode app|core] <tree-dir>}"
	shift 2
fi
case "$mode" in
app | core) ;;
*)
	echo "unknown --mode $mode (want app or core)" >&2
	exit 2
	;;
esac

tree="${1:?usage: gen_golden.sh [--mode app|core] <tree-dir>}"
tree="${tree%/}"
out="$(dirname "$tree")/golden/$(basename "$tree")"
mkdir -p "$out"

# OS/file-manager cruft (spec §3.2 items 2–3) — excluded in both modes.
is_cruft() {
	local base="$1"
	case "$base" in
	.DS_Store | Thumbs.db | .directory | .webapp) return 0 ;;
	esac
	case "$base" in
	.webapp-owncloud-*) return 0 ;;
	esac
	return 1
}

# is_excluded reports whether the relative key must be excluded for $mode.
is_excluded() {
	local rel="$1" base top
	base="$(basename "$rel")"
	if is_cruft "$base"; then
		return 0
	fi
	if [ "$mode" = "core" ]; then
		# Both signature files are excluded unconditionally by the legacy verifier.
		case "$rel" in
		core/signature.json | appinfo/signature.json | core/js/mimetypelist.js) return 0 ;;
		esac
		# Top-level folder exclusion on the first path segment only.
		top="${rel%%/*}"
		case "$top" in
		data | themes | config | apps | assets | lost+found) return 0 ;;
		esac
		return 1
	fi
	case "$rel" in
	appinfo/signature.json) return 0 ;;
	esac
	return 1
}

marker='#### DO NOT CHANGE ANYTHING ABOVE THIS LINE ####'

# hash_file returns the SHA-512 for $1 (relative key $2), applying the core-mode
# root .htaccess marker rule (§3.6). Byte-exact prefix extraction uses grep's
# byte offset + head -c, independent of the Go strings.Split implementation.
hash_file() {
	local f="$1" rel="$2" count offset
	if [ "$mode" = "core" ] && [ "$rel" = ".htaccess" ]; then
		# Count marker occurrences (not lines): the Go split hashes the prefix
		# only when the marker appears exactly once.
		count="$(grep -o -F -- "$marker" "$f" | wc -l | tr -d ' ')"
		if [ "$count" = "1" ]; then
			offset="$(grep -b -o -F -- "$marker" "$f" | head -1 | cut -d: -f1)"
			head -c "$offset" "$f" | sha512sum | cut -d' ' -f1
			return
		fi
	fi
	sha512sum "$f" | cut -d' ' -f1
}

# Collect (key, hash) pairs into a byte-sorted list.
pairs=()
while IFS= read -r -d '' f; do
	rel="${f#"$tree"/}"
	if is_excluded "$rel"; then
		continue
	fi
	h="$(hash_file "$f" "$rel")"
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
