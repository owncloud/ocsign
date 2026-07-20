package manifest_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/owncloud/ocsign/internal/manifest"
)

// allTrees are the golden-vector fixtures whose committed manifest.canonical.json
// was produced by the independent oracle testdata/gen_golden.sh (spec §8).
var allTrees = []string{"tree-basic", "tree-cruft", "tree-edge", "tree-unicode"}

func treePath(t *testing.T, name string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	return p
}

// goldenPath resolves a committed golden file, which lives under
// testdata/golden/<tree>/ (a sibling of the fixture trees, so Build never hashes
// it as a tree file).
func goldenPath(t *testing.T, tree, file string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "testdata", "golden", tree, file))
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	return p
}

// TestCanonicalMatchesGolden is the core conformance test (spec §8): recompute M
// from each tree and require it to equal the committed manifest.canonical.json
// byte-for-byte.
func TestCanonicalMatchesGolden(t *testing.T) {
	for _, tree := range allTrees {
		t.Run(tree, func(t *testing.T) {
			root := treePath(t, tree)
			want, err := os.ReadFile(goldenPath(t, tree, "manifest.canonical.json"))
			if err != nil {
				t.Fatalf("read golden: %v", err)
			}

			m, err := manifest.Build(root, manifest.ModeApp)
			if err != nil {
				t.Fatalf("Build: %v", err)
			}

			if got := m.Canonical(); string(got) != string(want) {
				t.Errorf("canonical bytes mismatch\n got: %s\nwant: %s", got, want)
			}
		})
	}
}

// TestCruftExcluded pins the app-mode exclusion list (spec §3.2): OS/file-manager
// cruft is not in the manifest, but a genuine app file (mimetypelist.js, which is
// core-only) is.
func TestCruftExcluded(t *testing.T) {
	root := treePath(t, "tree-cruft")
	m, err := manifest.Build(root, manifest.ModeApp)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	hashes := m.Hashes()

	excluded := []string{".DS_Store", "js/Thumbs.db", ".directory", ".webapp", ".webapp-owncloud-1.0"}
	for _, key := range excluded {
		if _, ok := hashes[key]; ok {
			t.Errorf("%q should be excluded but is present in the manifest", key)
		}
	}

	included := []string{"appinfo/info.xml", "js/app.js", "js/mimetypelist.js"}
	for _, key := range included {
		if _, ok := hashes[key]; !ok {
			t.Errorf("%q should be included but is missing from the manifest", key)
		}
	}
}

// TestSignatureFileExcluded pins that a pre-existing appinfo/signature.json is not
// hashed (spec §3.2 item 1).
func TestSignatureFileExcluded(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "appinfo/info.xml", "<info><id>example-app</id></info>")
	writeFile(t, root, "appinfo/signature.json", `{"v":2}`)
	writeFile(t, root, "js/app.js", "x")

	m, err := manifest.Build(root, manifest.ModeApp)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if _, ok := m.Hashes()["appinfo/signature.json"]; ok {
		t.Error("appinfo/signature.json must be excluded from the manifest")
	}
	if _, ok := m.Hashes()["appinfo/info.xml"]; !ok {
		t.Error("appinfo/info.xml must be included")
	}
}

// TestByteOrdering pins the '.' (0x2E) < '/' (0x2F) ordering (spec §3.5, tree-edge).
func TestByteOrdering(t *testing.T) {
	root := treePath(t, "tree-edge")
	m, err := manifest.Build(root, manifest.ModeApp)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	keys := m.Keys()

	posOf := func(k string) int {
		for i, key := range keys {
			if key == k {
				return i
			}
		}
		return -1
	}
	if a, b := posOf("a.b"), posOf("a/b"); a == -1 || b == -1 || a >= b {
		t.Errorf("expected a.b (%d) to sort before a/b (%d)", a, b)
	}
}

// TestPathSeparatorNormalized pins that keys use forward slashes with no leading
// slash or ./ prefix (spec §3.3).
func TestPathSeparatorNormalized(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "appinfo/info.xml", "<info><id>example-app</id></info>")
	writeFile(t, root, filepath.Join("lib", "Controller", "Page.php"), "<?php")

	m, err := manifest.Build(root, manifest.ModeApp)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if _, ok := m.Hashes()["lib/Controller/Page.php"]; !ok {
		t.Errorf("expected forward-slash key lib/Controller/Page.php, got keys %v", m.Keys())
	}
}

// TestEmptyFileHashed pins that a 0-byte file is included with the SHA-512 of the
// empty input (spec §8 tree-edge).
func TestEmptyFileHashed(t *testing.T) {
	const emptySHA512 = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" +
		"47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
	root := treePath(t, "tree-edge")
	m, err := manifest.Build(root, manifest.ModeApp)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got := m.Hashes()["empty.txt"]; got != emptySHA512 {
		t.Errorf("empty.txt hash = %q, want %q", got, emptySHA512)
	}
}

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
}
