#!/bin/bash

# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# A script to pack the config_file_ui app and deploy it to a DUT.

# shellcheck disable=SC2154
if [[ "${CROS_WORKON_SRCROOT}" = "" ]]; then
  echo "This script must run inside the CrOS SDK"
  exit 1
fi

SCRIPT_ROOT="${CROS_WORKON_SRCROOT}/src/scripts"
# shellcheck disable=SC1091
. "${SCRIPT_ROOT}/common.sh" || exit 1
# shellcheck disable=SC1091
. "${SCRIPT_ROOT}/remote_access.sh" || exit 1

#DEFINE_string remote "" "remote device to deploy to"
DEFINE_string remote_dir "/usr/local" "remote directory to deploy to"

# Parse command line.
FLAGS "$@" || exit 1
eval set -- "${FLAGS_ARGV}"

# Only now can we die on error.  shflags functions leak non-zero error codes,
# so will die prematurely if 'switch_to_strict_mode' is specified before now.
switch_to_strict_mode

GO_SRCROOT="${CROS_WORKON_SRCROOT}/src/platform2/camera/go/src"
PKG="chromiumos/camera/config_file_ui"
OUT_DIR="${GO_SRCROOT}/${PKG}/out"
STATIC_DIRS="css js templates setting_files"
APP_OUTPUT="${GO_SRCROOT}/${PKG}/app.sh"
TAST_GOPATH="${CROS_WORKON_SRCROOT}/src/platform/tast"
TAST_GOPATH="${TAST_GOPATH}:${CROS_WORKON_SRCROOT}/src/platform/tast-tests"

cleanup() {
  cleanup_remote_access
  rm -rf "${TMP}"
  rm -rf "${OUT_DIR}"
}

build_gopkg() {
  info "Building app in ${OUT_DIR}..."

  rm -rf "${OUT_DIR}"
  mkdir -p "${OUT_DIR}"
  # TODO(jcliang): select the cross compiler based on the remote board.
  GO111MODULE=off GOPATH="${GO_SRCROOT}/..:${TAST_GOPATH}:/usr/lib/gopath" \
  CGO_ENABLED=0 \
    x86_64-cros-linux-gnu-go build -o "${OUT_DIR}" "${PKG}"

  for d in ${STATIC_DIRS}; do
    cp -r "${GO_SRCROOT}/${PKG}/${d}" "${OUT_DIR}"
  done
}

pack() {
# shellcheck disable=SC2016
  local app_head='#!/bin/bash
cleanup() {
  rm -rf "${TMP}"
}
main() {
  trap cleanup EXIT
  TMP=$(mktemp -d /usr/local/config_file_ui.XXXXXX)
  if [[ "${TMP}" = "" ]]; then
    exit 1
  fi
  pushd "${TMP}" || exit 1
  base64 -d << APP_EOF | tar -xj'

# shellcheck disable=SC2016
  local app_tail='APP_EOF
  "${TMP}"/config_file_ui
  popd || exit 1
}
main "$@"'

  info "Packing app into ${APP_OUTPUT}..."

  echo "${app_head}" > "${APP_OUTPUT}" || exit 1
  tar -cj -C "${OUT_DIR}" . | base64 >> "${APP_OUTPUT}" || exit 1
  echo "${app_tail}" >> "${APP_OUTPUT}" || exit 1
  chmod +x "${APP_OUTPUT}"
}

deploy() {
  remote_cp_to "${APP_OUTPUT}" "${FLAGS_remote_dir}"
  local remote_path="${FLAGS_remote}:${FLAGS_remote_dir}"
  info "Deployed app to ${remote_path}/$(basename "${APP_OUTPUT}")"
}

main() {
  if [[ "${FLAGS_remote}" = "" ]]; then
    die_notrace "remote unspecified"
  fi
  trap cleanup EXIT
  TMP=$(mktemp -d /tmp/deploy_dut.XXXXXX)
  remote_access_init
  build_gopkg
  pack
  deploy
}

main "$@"
