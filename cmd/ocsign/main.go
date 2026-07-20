// Command ocsign produces a canonical, signed signature.json (schema v2) for an
// ownCloud app, decoupled from the server. See the package docs in internal/cli
// for the command-line contract and exit codes.
package main

import (
	"os"

	"github.com/owncloud/ocsign/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
