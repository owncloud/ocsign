package cli_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/owncloud/ocsign/internal/cli"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "testdata", name))
	if err != nil {
		t.Fatalf("abs: %v", err)
	}
	return p
}

func key(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(fixture(t, "keys"), name)
}

// run invokes the CLI with args and captures stdout/stderr and the exit code.
func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := cli.Run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// copyTree copies a fixture tree into a writable temp dir so signing can write
// signature.json without mutating testdata.
func copyTree(t *testing.T, name string) string {
	t.Helper()
	src := fixture(t, name)
	dst := t.TempDir()
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
	if err != nil {
		t.Fatalf("copyTree: %v", err)
	}
	return dst
}

// TestSignBasic signs tree-basic with the EC key and writes a valid
// appinfo/signature.json whose hashes equal the canonical bytes M.
func TestSignBasic(t *testing.T) {
	tree := copyTree(t, "tree-basic")
	code, _, stderr := run(t,
		"--path", tree,
		"--key", key(t, "ec-leaf.key"),
		"--cert", key(t, "ec-leaf.crt"),
		"--chain", key(t, "ec-intermediate.crt"),
	)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr)
	}

	out := filepath.Join(tree, "appinfo", "signature.json")
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("read signature.json: %v", err)
	}

	var env struct {
		V      int             `json:"v"`
		Alg    string          `json:"alg"`
		Hashes json.RawMessage `json:"hashes"`
	}
	if err := json.Unmarshal(data, &env); err != nil {
		t.Fatalf("signature.json invalid: %v", err)
	}
	if env.V != 2 || env.Alg != "ecdsa-p384-sha384" {
		t.Errorf("v=%d alg=%q", env.V, env.Alg)
	}

	want, err := os.ReadFile(filepath.Join(fixture(t, "golden"), "tree-basic", "manifest.canonical.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(env.Hashes, want) {
		t.Errorf("hashes != canonical M\n got: %s\nwant: %s", env.Hashes, want)
	}
}

// TestDryRunWritesNothing prints to stdout and leaves no signature.json (§2).
func TestDryRunWritesNothing(t *testing.T) {
	tree := copyTree(t, "tree-basic")
	code, stdout, stderr := run(t,
		"--path", tree,
		"--key", key(t, "ec-leaf.key"),
		"--cert", key(t, "ec-leaf.crt"),
		"--dry-run",
	)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr)
	}
	if len(stdout) == 0 {
		t.Error("dry-run should print to stdout")
	}
	if _, err := os.Stat(filepath.Join(tree, "appinfo", "signature.json")); !os.IsNotExist(err) {
		t.Error("dry-run must not write signature.json")
	}
}

// TestMissingFlag is a usage error -> exit 1 (§2).
func TestMissingFlag(t *testing.T) {
	code, _, _ := run(t, "--key", key(t, "ec-leaf.key"))
	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
}

// TestUnreadablePath is an input error -> exit 1 (§2).
func TestUnreadablePath(t *testing.T) {
	code, _, _ := run(t,
		"--path", filepath.Join(t.TempDir(), "does-not-exist"),
		"--key", key(t, "ec-leaf.key"),
		"--cert", key(t, "ec-leaf.crt"),
	)
	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
}

// TestKeyCertMismatch: key does not match cert -> signing error, exit 2 (§2).
func TestKeyCertMismatch(t *testing.T) {
	tree := copyTree(t, "tree-basic")
	code, _, _ := run(t,
		"--path", tree,
		"--key", key(t, "ec-leaf.key"),
		"--cert", key(t, "rsa-leaf.crt"), // wrong cert for this key
	)
	if code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
}

// TestCNMismatch: cert CN != appId -> exit 2 (§2). tree-cn-mismatch declares a
// different app id than the leaf CN (example-app).
func TestCNMismatch(t *testing.T) {
	tree := copyTree(t, "tree-basic")
	// Rewrite info.xml so the app id no longer matches the leaf CN example-app.
	infoPath := filepath.Join(tree, "appinfo", "info.xml")
	if err := os.WriteFile(infoPath, []byte(`<info><id>other-app</id></info>`), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, _ := run(t,
		"--path", tree,
		"--key", key(t, "ec-leaf.key"),
		"--cert", key(t, "ec-leaf.crt"),
	)
	if code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
}

// TestVersionFlag prints the build version and exits 0 without requiring the
// signing flags.
func TestVersionFlag(t *testing.T) {
	code, stdout, stderr := run(t, "--version")
	if code != 0 {
		t.Fatalf("exit = %d, want 0; stderr: %s", code, stderr)
	}
	if !bytes.Contains([]byte(stdout), []byte("ocsign")) {
		t.Errorf("--version output should mention ocsign, got %q", stdout)
	}
}

// TestCoreNotImplemented: --core exits with a clear error (scope).
func TestCoreNotImplemented(t *testing.T) {
	tree := copyTree(t, "tree-basic")
	code, _, stderr := run(t,
		"--path", tree,
		"--key", key(t, "ec-leaf.key"),
		"--cert", key(t, "ec-leaf.crt"),
		"--core",
	)
	if code == 0 {
		t.Error("--core should not succeed yet")
	}
	if stderr == "" {
		t.Error("--core should explain it is not implemented")
	}
}

// TestAttestNotImplemented: --attest exits 3 with a clear error (scope, §6).
func TestAttestNotImplemented(t *testing.T) {
	tree := copyTree(t, "tree-basic")
	code, _, stderr := run(t,
		"--path", tree,
		"--key", key(t, "ec-leaf.key"),
		"--cert", key(t, "ec-leaf.crt"),
		"--attest",
	)
	if code != 3 {
		t.Errorf("exit = %d, want 3", code)
	}
	if stderr == "" {
		t.Error("--attest should explain it is not implemented")
	}
}
