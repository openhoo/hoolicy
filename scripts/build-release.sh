#!/usr/bin/env bash
set -euo pipefail

version="${VERSION:?VERSION is required}"
commit="${COMMIT:-$(git rev-parse HEAD)}"
build_date="${BUILD_DATE:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
source_date_epoch="${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct HEAD)}"

if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]]; then
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
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" go build -trimpath \
    -ldflags="-s -w -X main.version=${version} -X main.commit=${commit} -X main.date=${build_date}" \
    -o "$stage/hoolicy${suffix}" ./cmd/hoolicy
  cp LICENSE README.md "$stage/"
  if [[ "$goos" == "windows" ]]; then
    (cd "$temporary" && zip -X -qr "$OLDPWD/dist/${name}.zip" "$name")
  else
    tar --sort=name --owner=0 --group=0 --numeric-owner --mtime="@${source_date_epoch}" \
      -czf "dist/${name}.tar.gz" -C "$temporary" "$name"
  fi
}

build_one linux amd64 ""
build_one linux arm64 ""
build_one darwin amd64 ""
build_one darwin arm64 ""
build_one windows amd64 ".exe"
