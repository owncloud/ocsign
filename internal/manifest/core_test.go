package manifest_test

import (
	"crypto/sha512"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/owncloud/ocsign/internal/manifest"
)

// coreTrees are the golden-vector fixtures signed in core mode (spec §3.6).
var coreTrees = []string{"tree-core"}

// testMarker is the .htaccess baseline delimiter, pinned literally here so the
// test is an independent check on the manifest package's own constant.
const testMarker = "#### DO NOT CHANGE ANYTHING ABOVE THIS LINE ####"

// TestCoreCanonicalMatchesGolden is the core-mode conformance test (spec §8):
// recompute M from each core fixture and require it to equal the committed
// manifest.canonical.json byte-for-byte.
func TestCoreCanonicalMatchesGolden(t *testing.T) {
	for _, tree := range coreTrees {
		t.Run(tree, func(t *testing.T) {
			root := treePath(t, tree)
			want, err := os.ReadFile(goldenPath(t, tree, "manifest.canonical.json"))
			if err != nil {
				t.Fatalf("read golden: %v", err)
			}

			m, err := manifest.Build(root, manifest.ModeCore)
			if err != nil {
				t.Fatalf("Build: %v", err)
			}
			if got := m.Canonical(); string(got) != string(want) {
				t.Errorf("canonical bytes mismatch\n got: %s\nwant: %s", got, want)
			}
		})
	}
}

// TestCoreExclusions pins the core-mode exclusion set (spec §3.6): the core
// signature file, mimetypelist.js, and the top-level data/themes/config/apps/
// assets/lost+found folders are excluded; genuine core files (including a path
// whose first segment merely resembles an excluded folder) are kept. OS cruft is
// covered separately by tree-cruft, which shares the exclusion code path.
func TestCoreExclusions(t *testing.T) {
	m, err := manifest.Build(treePath(t, "tree-core"), manifest.ModeCore)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	hashes := m.Hashes()

	excluded := []string{
		"core/signature.json",
		"core/js/mimetypelist.js",
		"data/secret.txt",
		"themes/default/theme.php",
		"config/config.php",
		"apps/foo.php",
		"assets/a.css",
		"lost+found/orphan",
	}
	for _, key := range excluded {
		if _, ok := hashes[key]; ok {
			t.Errorf("%q should be excluded but is present in the core manifest", key)
		}
	}

	included := []string{
		"index.php",
		"status.php",
		".htaccess",
		".user.ini",
		"core/index.php",
		"core/js/other.js",
		"core/apps-like/x.php", // first segment is "core", not the excluded "apps"
	}
	for _, key := range included {
		if _, ok := hashes[key]; !ok {
			t.Errorf("%q should be included but is missing from the core manifest", key)
		}
	}
}

// sha512hex returns the lowercase-hex SHA-512 of b, the manifest hash encoding.
func sha512hex(b []byte) string {
	sum := sha512.Sum512(b)
	return hex.EncodeToString(sum[:])
}

// TestCoreHtaccessMarkerPrefixHashed pins the §3.6 rule: the root .htaccess is
// hashed over the bytes BEFORE the marker when it occurs exactly once.
func TestCoreHtaccessMarkerPrefixHashed(t *testing.T) {
	root := t.TempDir()
	prefix := "# baseline\nOptions -Indexes\n"
	whole := prefix + testMarker + "\ndynamic content\n"
	writeFile(t, root, ".htaccess", whole)

	m, err := manifest.Build(root, manifest.ModeCore)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	got := m.Hashes()[".htaccess"]
	if want := sha512hex([]byte(prefix)); got != want {
		t.Errorf(".htaccess hash = %q, want prefix hash %q", got, want)
	}
	if got == sha512hex([]byte(whole)) {
		t.Error(".htaccess must not be hashed over the whole file when the marker is present")
	}
}

// TestCoreHtaccessNoMarkerNormalHash pins that a root .htaccess without the
// marker is hashed over the whole file (fall-through).
func TestCoreHtaccessNoMarkerNormalHash(t *testing.T) {
	root := t.TempDir()
	whole := "# no marker here\nOptions -Indexes\n"
	writeFile(t, root, ".htaccess", whole)

	m, err := manifest.Build(root, manifest.ModeCore)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got, want := m.Hashes()[".htaccess"], sha512hex([]byte(whole)); got != want {
		t.Errorf(".htaccess hash = %q, want whole-file hash %q", got, want)
	}
}

// TestCoreHtaccessDoubleMarkerNormalHash pins that a marker appearing more than
// once disables the prefix rule (mirrors the legacy explode()+count()===2).
func TestCoreHtaccessDoubleMarkerNormalHash(t *testing.T) {
	root := t.TempDir()
	whole := "a\n" + testMarker + "\nb\n" + testMarker + "\nc\n"
	writeFile(t, root, ".htaccess", whole)

	m, err := manifest.Build(root, manifest.ModeCore)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got, want := m.Hashes()[".htaccess"], sha512hex([]byte(whole)); got != want {
		t.Errorf(".htaccess hash = %q, want whole-file hash %q (double marker)", got, want)
	}
}

// TestCoreNestedHtaccessNormalHash pins that the marker rule is root-only: a
// nested .htaccess containing the marker is still hashed over the whole file.
func TestCoreNestedHtaccessNormalHash(t *testing.T) {
	root := t.TempDir()
	whole := "deny\n" + testMarker + "\nmore\n"
	writeFile(t, root, filepath.Join("core", ".htaccess"), whole)

	m, err := manifest.Build(root, manifest.ModeCore)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got, want := m.Hashes()["core/.htaccess"], sha512hex([]byte(whole)); got != want {
		t.Errorf("core/.htaccess hash = %q, want whole-file hash %q", got, want)
	}
}

// TestCoreUserIniNormalHash documents that .user.ini has no special handling:
// the legacy "reset to defaults" is a no-op, so a plain file hash matches.
func TestCoreUserIniNormalHash(t *testing.T) {
	root := t.TempDir()
	content := "upload_max_filesize=513M\npost_max_size=513M\n"
	writeFile(t, root, ".user.ini", content)

	m, err := manifest.Build(root, manifest.ModeCore)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got, want := m.Hashes()[".user.ini"], sha512hex([]byte(content)); got != want {
		t.Errorf(".user.ini hash = %q, want whole-file hash %q", got, want)
	}
}

// TestAppModeUnaffected is a regression guard: the app-mode manifest for
// tree-basic still matches its golden after the mode-aware Build change.
func TestAppModeUnaffected(t *testing.T) {
	root := treePath(t, "tree-basic")
	want, err := os.ReadFile(goldenPath(t, "tree-basic", "manifest.canonical.json"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	m, err := manifest.Build(root, manifest.ModeApp)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if got := m.Canonical(); string(got) != string(want) {
		t.Errorf("app-mode canonical bytes changed\n got: %s\nwant: %s", got, want)
	}
}
