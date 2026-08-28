#!/usr/bin/env bash
set -euo pipefail

version="${VERSION:-$(tr -d '[:space:]' < VERSION)}"
commit="${COMMIT:-$(git rev-parse HEAD)}"
source_date_epoch="${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct HEAD)}"
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT

for run in one two; do
  HOOLICY_REPRODUCIBILITY_CHECK=1 DIST_DIR="$temporary/$run" VERSION="$version" COMMIT="$commit" SOURCE_DATE_EPOCH="$source_date_epoch" scripts/build-release.sh
  (cd "$temporary/$run" && sha256sum -- * | LC_ALL=C sort -k2) > "$temporary/$run.sha256"
done

diff -u "$temporary/one.sha256" "$temporary/two.sha256"
echo "Archive bytes reproducible for $version at $commit (qualification mode; publication checks remain enforced by build-release.sh)"
