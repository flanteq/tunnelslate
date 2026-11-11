package buildinfo

import (
	_ "embed"
	"strings"
)

//go:embed VERSION
var versionFile string

// Version belongs to the built binary, independently of the mounted data.
var Version = strings.TrimSpace(versionFile)
