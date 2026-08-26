// Package hoolicy exposes the compile-time extension entry point for custom
// Hoolicy binaries. Standard CLI users should install cmd/hoolicy instead.
package hoolicy

import (
	"context"
	"fmt"
	"os"

	"github.com/openhoo/hoolicy/internal/cli"
	"github.com/openhoo/hoolicy/internal/rules"
	"github.com/openhoo/hoolicy/sdk"
)

type BuildInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Date    string `json:"date"`
}

type RegisterFunc func(*sdk.Registry) error

func NewRegistry() (*sdk.Registry, error) {
	registry := sdk.NewRegistry()
	if err := rules.RegisterCore(registry); err != nil {
		return nil, err
	}
	return registry, nil
}

func Run(ctx context.Context, args []string, info BuildInfo, register RegisterFunc) int {
	registry, err := NewRegistry()
	if err != nil {
		return 2
	}
	if register != nil {
		if err := register(registry); err != nil {
			fmt.Fprintf(os.Stderr, "hoolicy: register custom rules: %v\n", err)
			return 2
		}
	}
	return cli.RunWithRegistry(ctx, args, cli.BuildInfo(info), registry)
}
