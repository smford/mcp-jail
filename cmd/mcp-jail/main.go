package main

import (
	"github.com/smford/mcp-jail/internal/cli"
)

var (
	version = "0.5.0"
	commit  = "none"
	date    = "unknown"
)

func main() {
	cli.SetVersion(version, commit, date)
	cli.Execute()
}
