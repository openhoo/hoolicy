package main

import (
	"context"
	"fmt"
	"os"

	"github.com/openhoo/hoolicy"
	"github.com/openhoo/hoolicy/sdk"
)

type reviewedKind struct{}

func (reviewedKind) Validate(rule sdk.Rule) error {
	if len(rule.Files) == 0 {
		return fmt.Errorf("rule %s requires files", rule.ID)
	}
	return nil
}

func (reviewedKind) Evaluate(ctx context.Context, input sdk.EvalContext, rule sdk.Rule) ([]sdk.Finding, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	files, err := input.Repository.Match(rule.Files, rule.Exclude)
	if err != nil {
		return nil, err
	}
	if len(files) > 0 {
		return nil, nil
	}
	return []sdk.Finding{{Message: "Required reviewed input is missing", Key: "missing"}}, nil
}

func main() {
	code := hoolicy.Run(context.Background(), os.Args[1:], hoolicy.BuildInfo{Version: "company"}, func(registry *sdk.Registry) error {
		return registry.Register("company.reviewed", reviewedKind{})
	})
	os.Exit(code)
}
