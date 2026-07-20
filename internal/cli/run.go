// Package cli implements the ocsign command-line contract: flag parsing,
// orchestration of manifest → sign → envelope, and the exit-code discipline
// (spec §2).
package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/owncloud/ocsign/internal/appinfo"
	"github.com/owncloud/ocsign/internal/keys"
	"github.com/owncloud/ocsign/internal/manifest"
	"github.com/owncloud/ocsign/internal/sign"
	"github.com/owncloud/ocsign/internal/signature"
	"github.com/owncloud/ocsign/internal/version"
)

// Exit codes (spec §2).
const (
	exitOK          = 0
	exitUsage       = 1 // usage / input error
	exitSigning     = 2 // signing error (key/cert mismatch, unsupported key type)
	exitAttestation = 3 // --attest requested but unavailable/failed
)

type options struct {
	path        string
	key         string
	cert        string
	chain       string
	core        bool
	attest      bool
	attestURL   string
	out         string
	dryRun      bool
	showVersion bool
}

// Run parses args (excluding the program name), executes the signing flow, and
// returns the process exit code. stdout/stderr are injected for testability.
func Run(args []string, stdout, stderr io.Writer) int {
	opts, err := parseFlags(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitOK
		}
		fmt.Fprintln(stderr, "error:", err)
		return exitUsage
	}

	if opts.showVersion {
		fmt.Fprintf(stdout, "ocsign %s\n", version.Version)
		return exitOK
	}

	if err := run(opts, stdout); err != nil {
		var ce codedError
		if errors.As(err, &ce) {
			fmt.Fprintln(stderr, "error:", ce.err)
			return ce.code
		}
		fmt.Fprintln(stderr, "error:", err)
		return exitUsage
	}
	return exitOK
}

func parseFlags(args []string, stderr io.Writer) (*options, error) {
	fs := flag.NewFlagSet("ocsign", flag.ContinueOnError)
	fs.SetOutput(stderr)

	opts := &options{}
	fs.StringVar(&opts.path, "path", "", "path to the app root directory to sign (required)")
	fs.StringVar(&opts.key, "key", "", "path to the signer's PEM private key (required)")
	fs.StringVar(&opts.cert, "cert", "", "path to the issued leaf certificate PEM (required)")
	fs.StringVar(&opts.chain, "chain", "", "path to a PEM file with intermediate cert(s) to embed")
	fs.BoolVar(&opts.core, "core", false, `sign the core server root (leaf CN must be "core"); writes core/signature.json`)
	fs.BoolVar(&opts.attest, "attest", false, "attach a Mode-2 attestation token (not yet implemented)")
	fs.StringVar(&opts.attestURL, "attest-repo", "", "owner/repo of the attestation workflow")
	fs.StringVar(&opts.out, "out", "", "override output path for signature.json")
	fs.BoolVar(&opts.dryRun, "dry-run", false, "compute and print; write nothing")
	fs.BoolVar(&opts.showVersion, "version", false, "print the ocsign version and exit")

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	// --version is informational and needs none of the signing flags.
	if opts.showVersion {
		return opts, nil
	}

	var missing []string
	if opts.path == "" {
		missing = append(missing, "--path")
	}
	if opts.key == "" {
		missing = append(missing, "--key")
	}
	if opts.cert == "" {
		missing = append(missing, "--cert")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required flag(s): %v", missing)
	}
	return opts, nil
}

// codedError carries the intended exit code alongside an error.
type codedError struct {
	code int
	err  error
}

func (c codedError) Error() string { return c.err.Error() }
func (c codedError) Unwrap() error { return c.err }

func coded(code int, err error) error { return codedError{code: code, err: err} }

// coreIdentity is the reserved leaf-CN that authorizes signing the core server
// root (spec-core-verifier §7). Core has no appinfo/info.xml app id, so the CN
// is compared to this literal rather than derived and validated as an appId.
const coreIdentity = "core"

func run(opts *options, stdout io.Writer) error {
	mode := manifest.ModeApp
	if opts.core {
		mode = manifest.ModeCore
	}

	// Validate the app path up front so a bad --path is a clean input error.
	info, err := os.Stat(opts.path)
	if err != nil {
		return coded(exitUsage, fmt.Errorf("--path: %w", err))
	}
	if !info.IsDir() {
		return coded(exitUsage, fmt.Errorf("--path %q is not a directory", opts.path))
	}

	key, err := keys.LoadPrivateKey(opts.key)
	if err != nil {
		return coded(exitUsage, fmt.Errorf("--key: %w", err))
	}
	cert, err := keys.LoadCertificate(opts.cert)
	if err != nil {
		return coded(exitUsage, fmt.Errorf("--cert: %w", err))
	}

	// Key/cert consistency checks (spec §2) — signing errors, exit 2.
	if !keys.PublicKeyMatches(key, cert) {
		return coded(exitSigning, errors.New("--key public key does not match --cert subject public key"))
	}
	if opts.core {
		// Core has no app id; the leaf must carry the reserved core identity.
		if cert.Subject.CommonName != coreIdentity {
			return coded(exitSigning, fmt.Errorf(
				"cert CN %q does not match reserved core identity %q", cert.Subject.CommonName, coreIdentity))
		}
	} else {
		appID, err := appinfo.AppID(opts.path)
		if err != nil {
			return coded(exitSigning, err)
		}
		if err := appinfo.ValidateCN(cert.Subject.CommonName); err != nil {
			return coded(exitSigning, err)
		}
		if cert.Subject.CommonName != appID {
			return coded(exitSigning, fmt.Errorf(
				"cert CN %q does not match app id %q", cert.Subject.CommonName, appID))
		}
	}

	var chain []string
	if opts.chain != "" {
		chainCerts, err := keys.LoadChain(opts.chain)
		if err != nil {
			return coded(exitUsage, fmt.Errorf("--chain: %w", err))
		}
		chain = encodeChain(chainCerts)
	}

	// Build the canonical manifest bytes M and sign them (§3, §4).
	m, err := manifest.Build(opts.path, mode)
	if err != nil {
		return coded(exitUsage, fmt.Errorf("build manifest: %w", err))
	}
	canonical := m.Canonical()

	alg, sigB64, err := sign.Sign(key, canonical)
	if err != nil {
		return coded(exitSigning, err)
	}

	env := signature.Envelope{
		Alg:       alg,
		Hashes:    canonical,
		Signature: sigB64,
		Leaf:      encodeCertPEM(cert.Raw),
		Chain:     chain,
	}
	out, err := env.Marshal()
	if err != nil {
		return coded(exitUsage, fmt.Errorf("marshal signature.json: %w", err))
	}

	// Attestation is additive; a failure must not corrupt the Mode-1 output
	// (spec §6). Since attestation is not yet implementable, refuse before
	// writing anything.
	if opts.attest {
		return coded(exitAttestation, errors.New(
			"--attest (Mode-2 attestation) is not yet implemented: the bind(H,T) "+
				"token layout and result delivery are not yet finalized"))
	}

	if opts.dryRun {
		fmt.Fprintf(stdout, "manifest (canonical bytes M):\n%s\n\n", canonical)
		fmt.Fprintf(stdout, "signature.json:\n%s\n", out)
		return nil
	}

	outPath := opts.out
	if outPath == "" {
		if opts.core {
			outPath = filepath.Join(opts.path, "core", "signature.json")
		} else {
			outPath = filepath.Join(opts.path, "appinfo", "signature.json")
		}
	}
	if err := os.WriteFile(outPath, out, 0o644); err != nil {
		return coded(exitUsage, fmt.Errorf("write %s: %w", outPath, err))
	}
	fmt.Fprintf(stdout, "wrote %s\n", outPath)
	return nil
}
