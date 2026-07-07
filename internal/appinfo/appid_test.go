package appinfo_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/DeepDiver1975/ocsign/internal/appinfo"
)

// TestAppID reads the id from info.xml and canonicalizes it per verifier §7 /
// design §4.1: ASCII-only case-fold, then validate ^[a-z][a-z0-9_.-]{2,63}$.
func TestAppID(t *testing.T) {
	cases := []struct {
		name    string
		xml     string
		want    string
		wantErr bool
	}{
		{
			name: "simple id",
			xml:  `<?xml version="1.0"?><info><id>example-app</id></info>`,
			want: "example-app",
		},
		{
			name: "uppercase is ascii case-folded",
			xml:  `<info><id>Example_App</id></info>`,
			want: "example_app",
		},
		{
			name: "dot is allowed",
			xml:  `<info><id>example.app</id></info>`,
			want: "example.app",
		},
		{
			name: "minimum length three accepted",
			xml:  `<info><id>abc</id></info>`,
			want: "abc",
		},
		{
			name:    "invalid characters rejected",
			xml:     `<info><id>bad id!</id></info>`,
			wantErr: true,
		},
		{
			name:    "single character rejected",
			xml:     `<info><id>a</id></info>`,
			wantErr: true,
		},
		{
			name:    "two characters rejected (min length is three)",
			xml:     `<info><id>ab</id></info>`,
			wantErr: true,
		},
		{
			name:    "leading dot rejected (must start with a letter)",
			xml:     `<info><id>.app</id></info>`,
			wantErr: true,
		},
		{
			name:    "missing id rejected",
			xml:     `<info><name>no id here</name></info>`,
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			appinfoDir := filepath.Join(dir, "appinfo")
			if err := os.MkdirAll(appinfoDir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(appinfoDir, "info.xml"), []byte(tc.xml), 0o644); err != nil {
				t.Fatal(err)
			}

			got, err := appinfo.AppID(dir)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("AppID: %v", err)
			}
			if got != tc.want {
				t.Errorf("AppID = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestValidateCN validates the leaf CN strictly with no normalization (§7).
func TestValidateCN(t *testing.T) {
	if err := appinfo.ValidateCN("example-app"); err != nil {
		t.Errorf("valid CN rejected: %v", err)
	}
	if err := appinfo.ValidateCN("example.app"); err != nil {
		t.Errorf("dotted CN rejected: %v", err)
	}
	if err := appinfo.ValidateCN("Example-App"); err == nil {
		t.Error("uppercase CN must be rejected (no normalization)")
	}
	if err := appinfo.ValidateCN("x"); err == nil {
		t.Error("too-short CN must be rejected")
	}
	if err := appinfo.ValidateCN("ab"); err == nil {
		t.Error("two-character CN must be rejected (min length is three)")
	}
}
