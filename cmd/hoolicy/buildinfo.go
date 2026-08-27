//go:build !hoolicy_release

package main

import (
	"runtime/debug"
	"strings"

	"github.com/openhoo/hoolicy"
)

func resolveBuildInfo(info hoolicy.BuildInfo) hoolicy.BuildInfo {
	build, ok := debug.ReadBuildInfo()
	if !ok {
		return info
	}
	return resolveBuildInfoFrom(info, build)
}

func resolveBuildInfoFrom(info hoolicy.BuildInfo, build *debug.BuildInfo) hoolicy.BuildInfo {
	if info.Version == "dev" && build.Main.Version != "" && build.Main.Version != "(devel)" {
		info.Version = strings.TrimPrefix(build.Main.Version, "v")
	}
	for _, setting := range build.Settings {
		switch setting.Key {
		case "vcs.revision":
			if info.Commit == "unknown" && setting.Value != "" {
				info.Commit = setting.Value
			}
		case "vcs.time":
			if info.Date == "unknown" && setting.Value != "" {
				info.Date = setting.Value
			}
		}
	}
	return info
}
