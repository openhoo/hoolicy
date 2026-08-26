package main

import (
	"context"
	"os"

	"github.com/openhoo/hoolicy"
)

var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

func main() {
	os.Exit(hoolicy.Run(context.Background(), os.Args[1:], hoolicy.BuildInfo{
		Version: version,
		Commit:  commit,
		Date:    date,
	}, nil))
}
