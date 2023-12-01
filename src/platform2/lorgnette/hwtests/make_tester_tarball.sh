#!/bin/bash
# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

set -euo pipefail

die() {
  echo "$1" >&2
  exit 1
}

USAGE="Usage: $0 [--noupdate]"
BUILD_PACKAGES=1
while (( "$#" )); do
  case "$1" in
    --help|-h)
      echo "${USAGE}"
      exit
      ;;

    --noupdate)
      BUILD_PACKAGES=0
      ;;

    *)
      echo "Unrecognized argument $1"
      echo "${USAGE}"
      exit 1
      ;;
  esac
  shift
done


HWTESTS=/mnt/host/source/src/platform2/lorgnette/hwtests
OUT=/tmp/wwcb_mfp_tests.tar.gz
PACKAGES=(
  lorgnette-wwcb-tests
  imagemagick
)
BOARD=amd64-generic
SYSROOT="/build/${BOARD}"

# Files that need to be copied with their shared libraries.
SYSROOT_BINS=(
  /usr/bin/lorgnette_cli
  /usr/local/bin/identify
)

# Files that need to be copied, but don't need shared libraries.
SYSROOT_STATIC_BINS=(
  /usr/bin/test_scanner_capabilities
)

# Files to be installed from the current directory instead of sysroot.
HWTESTS_BINS=(
  wwcb_scan_test.sh
)

[[ -f /etc/cros_chroot_version ]] || \
  die "This script must be run inside the chroot."

[[ -d /build/amd64-generic ]] || \
  die "Run build_packages --board=amd64-generic first"

if [[ -f "${OUT}" ]]; then
  rm -f "${OUT}"
  echo "Cleaned up existing output ${OUT}"
fi

if [[ "${BUILD_PACKAGES}" -ne 0 ]]; then
  ~/trunk/src/scripts/build_packages --board=amd64-generic "${PACKAGES[@]}"
fi

cd "${HWTESTS}" || die "Can't cd to ${HWTESTS}"

for f in "${SYSROOT_BINS[@]}" "${SYSROOT_STATIC_BINS[@]}"; do
  [[ -f "${SYSROOT}${f}" ]] || \
    die "${SYSROOT}${f} is missing.  Run again without --noupdate."
done

ROOT=$(mktemp -d -t "wwcb_mfp.XXXXXX") || die "Can't create temp root"
PREFIX="${ROOT}/opt/wwcb_mfp"
mkdir -p "${PREFIX}"

lddtree -l \
  -R "${SYSROOT}" \
  --copy-to-tree="${PREFIX}" \
  --generate-wrappers \
  "${SYSROOT_BINS[@]}"

for f in "${SYSROOT_STATIC_BINS[@]}"; do
  src="${SYSROOT}${f}"
  instdir=$(dirname "${f}")
  install -m 0755 -t "${PREFIX}${instdir}" "${src}"
done
install -m 0755 -t "${PREFIX}/usr/bin" "${HWTESTS_BINS[@]}"

# ImageMagick has a lot of extra modules and config files that need to be
# included manually.
mkdir -p "${PREFIX}/usr/local/etc"
cp -r "${SYSROOT}/usr/local/etc/ImageMagick-7" "${PREFIX}/usr/local/etc"
mkdir -p "${PREFIX}/usr/local/lib64/ImageMagick-7"
cp -r "${SYSROOT}/usr/local/lib64/"ImageMagick-7*/* \
      "${PREFIX}/usr/local/lib64/ImageMagick-7"

mkdir -p "${ROOT}/bin"
install -m 0755 setup_shell "${ROOT}/bin/wwcb_mfp_env"

tar czvfC "${OUT}" "${ROOT}" .

rm -rf "${ROOT}"

echo "Tester tarball created as ${OUT}"
