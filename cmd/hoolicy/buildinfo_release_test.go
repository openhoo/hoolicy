//go:build hoolicy_release

package main

import (
	"testing"

	"github.com/openhoo/hoolicy"
)

func TestReleaseBuildInfoPreservesLinkerValues(t *testing.T) {
	t.Parallel()
	input := hoolicy.BuildInfo{Version: "1.2.3", Commit: "abc", Date: "today"}
	if got := resolveBuildInfo(input); got != input {
		t.Fatalf("release build info changed: %#v", got)
	}
}
