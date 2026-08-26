package main

import (
	"runtime/debug"
	"testing"

	"github.com/openhoo/hoolicy"
)

func TestResolveBuildInfoPreservesLinkerValues(t *testing.T) {
	t.Parallel()
	input := hoolicy.BuildInfo{Version: "1.2.3", Commit: "abc", Date: "today"}
	if got := resolveBuildInfo(input); got != input {
		t.Fatalf("linker build info changed: %#v", got)
	}
}

func TestResolveBuildInfoFromModuleMetadata(t *testing.T) {
	t.Parallel()
	input := hoolicy.BuildInfo{Version: "dev", Commit: "unknown", Date: "unknown"}
	build := &debug.BuildInfo{
		Main: debug.Module{Version: "v0.1.1"},
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "0123456789abcdef"},
			{Key: "vcs.time", Value: "2026-08-26T12:00:00Z"},
		},
	}
	want := hoolicy.BuildInfo{Version: "0.1.1", Commit: "0123456789abcdef", Date: "2026-08-26T12:00:00Z"}
	if got := resolveBuildInfoFrom(input, build); got != want {
		t.Fatalf("got %#v, want %#v", got, want)
	}
}
