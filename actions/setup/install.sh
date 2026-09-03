#!/usr/bin/env bash
set -euo pipefail

version="$HOOLICY_VERSION"
if [[ ! "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)([-+][0-9A-Za-z.-]+)?$ ]]; then
  echo "::error::Hoolicy version must be an unprefixed semantic version."
  exit 2
fi

case "$RUNNER_OS_VALUE" in
  Linux) os=linux ;;
  macOS) os=darwin ;;
  Windows) os=windows ;;
  *)
    echo "::error::Hoolicy does not publish binaries for runner.os '$RUNNER_OS_VALUE'."
    exit 2
    ;;
esac
case "$RUNNER_ARCH_VALUE" in
  X64) arch=amd64 ;;
  ARM64) arch=arm64 ;;
  *)
    echo "::error::Hoolicy does not publish binaries for runner.arch '$RUNNER_ARCH_VALUE'."
    exit 2
    ;;
esac
if [[ "$os" == windows && "$arch" != amd64 ]]; then
  echo "::error::Hoolicy does not publish Windows ARM64 binaries."
  exit 2
fi

stem="hoolicy_${version}_${os}_${arch}"
if [[ "$os" == windows ]]; then
  archive_name="${stem}.zip"
  binary_name=hoolicy.exe
else
  archive_name="${stem}.tar.gz"
  binary_name=hoolicy
fi

base_url="https://github.com/openhoo/hoolicy/releases/download/v${version}"
signature_identity="https://github.com/openhoo/hoolicy/.github/workflows/release.yml@refs/heads/main"
signature_issuer="https://token.actions.githubusercontent.com"
download_dir="$(mktemp -d "${RUNNER_TEMP}/hoolicy-download.XXXXXXXX")"
archive="${download_dir}/${archive_name}"
checksums="${download_dir}/SHA256SUMS"
archive_bundle="${archive}.sigstore.json"
checksums_bundle="${checksums}.sigstore.json"
curl --fail --location --silent --show-error --retry 3 --connect-timeout 30 --output "$archive" "${base_url}/${archive_name}"
curl --fail --location --silent --show-error --retry 3 --connect-timeout 30 --output "$checksums" "${base_url}/SHA256SUMS"
curl --fail --location --silent --show-error --retry 3 --connect-timeout 30 --output "$archive_bundle" "${base_url}/${archive_name}.sigstore.json"
curl --fail --location --silent --show-error --retry 3 --connect-timeout 30 --output "$checksums_bundle" "${base_url}/SHA256SUMS.sigstore.json"

if ! command -v cosign >/dev/null 2>&1; then
  echo "::error::Pinned Cosign verifier is unavailable."
  exit 1
fi
cosign verify-blob "$archive" --bundle "$archive_bundle" \
  --certificate-identity "$signature_identity" --certificate-oidc-issuer "$signature_issuer"
cosign verify-blob "$checksums" --bundle "$checksums_bundle" \
  --certificate-identity "$signature_identity" --certificate-oidc-issuer "$signature_issuer"

expected="$(awk -v name="$archive_name" '$2 == name { print $1 }' "$checksums")"
if [[ ! "$expected" =~ ^[0-9a-f]{64}$ ]]; then
  echo "::error::SHA256SUMS contains no unique digest for ${archive_name}."
  exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$archive" | awk '{ print $1 }')"
else
  actual="$(shasum -a 256 "$archive" | awk '{ print $1 }')"
fi
if [[ "$actual" != "$expected" ]]; then
  echo "::error::Checksum mismatch for ${archive_name}."
  exit 1
fi

extract_dir="$(mktemp -d "${RUNNER_TEMP}/hoolicy-extract.XXXXXXXX")"
if [[ "$os" == windows ]]; then
  unzip -q "$archive" -d "$extract_dir"
else
  tar -xzf "$archive" -C "$extract_dir"
fi
source_binary="$(find "$extract_dir" -type f -name "$binary_name" -print -quit)"
if [[ -z "$source_binary" ]]; then
  echo "::error::Archive ${archive_name} contains no ${binary_name}."
  exit 1
fi

bin_dir="$(mktemp -d "${RUNNER_TEMP}/hoolicy-bin.XXXXXXXX")"
cp "$source_binary" "${bin_dir}/${binary_name}"
chmod +x "${bin_dir}/${binary_name}"
"${bin_dir}/${binary_name}" version | grep -F "hoolicy ${version}"
echo "$bin_dir" >> "$GITHUB_PATH"
echo "version=$version" >> "$GITHUB_OUTPUT"
