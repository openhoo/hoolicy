#!/usr/bin/env bash
set -euo pipefail

version="${VERSION:?VERSION is required}"
commit="${COMMIT:-$(git rev-parse HEAD)}"
source_date_epoch="${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct HEAD)}"
build_date="${BUILD_DATE:-$(date -u --date="@${source_date_epoch}" +%Y-%m-%dT%H:%M:%SZ)}"
dist_dir="$(pwd)/dist"

if [[ ! "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$ ]]; then
  echo "VERSION must be semantic without a v prefix" >&2
  exit 2
fi

mkdir -p dist
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT

build_one() {
  local goos="$1"
  local goarch="$2"
  local suffix="$3"
  local name="hoolicy_${version}_${goos}_${goarch}"
  local stage="$temporary/$name"
  mkdir -p "$stage"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build -buildvcs=false -tags=hoolicy_release -trimpath \
    -ldflags="-s -w -buildid= -X main.version=${version} -X main.commit=${commit} -X main.date=${build_date}" \
    -o "$stage/hoolicy${suffix}" ./cmd/hoolicy
  cp LICENSE README.md "$stage/"
  touch --date="@${source_date_epoch}" "$stage/hoolicy${suffix}" "$stage/LICENSE" "$stage/README.md"
  if [[ "$goos" == "windows" ]]; then
    (cd "$temporary" && find "$name" -type f -print | LC_ALL=C sort | zip -X -q "$dist_dir/${name}.zip" -@)
  else
    tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@${source_date_epoch}" \
      -czf "$dist_dir/${name}.tar.gz" -C "$temporary" "$name"
  fi
}

build_one linux amd64 ""
build_one linux arm64 ""
build_one darwin amd64 ""
build_one darwin arm64 ""
build_one windows amd64 ".exe"
