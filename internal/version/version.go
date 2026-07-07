// Package version exposes the build version, set via -ldflags at release time.
package version

// Version is the ocsign build version. It is "dev" for non-release builds and is
// overwritten with the release tag (e.g. v0.1.0) by the release build:
//
//	go build -ldflags "-X github.com/DeepDiver1975/ocsign/internal/version.Version=v0.1.0"
var Version = "dev"
