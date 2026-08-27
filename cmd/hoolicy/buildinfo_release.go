//go:build hoolicy_release

package main

import "github.com/openhoo/hoolicy"

func resolveBuildInfo(info hoolicy.BuildInfo) hoolicy.BuildInfo {
	return info
}
