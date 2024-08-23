#!/bin/bash
# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Generate an error if a cros-workon-ed ebuild has missing dependencies.

# Set ebuild vars to make shellcheck happy.
: "${PV:=}" "${SYSROOT:=/}" "${T:=}"

# b/301462588 - The bazel stage2 tarball doesn't include `equery`, so skip this
# hook.
if [[ "${PV}" == "9999" ]] && type -P equery >/dev/null; then
  args=( --format=pretty )
  if [[ "${SYSROOT}" == "/build/"* ]]; then
    args+=( "--board=${SYSROOT##*/}" )
  else
    args+=( --no-default-board )
  fi
  args+=( --match --build-info="${T}/../build-info/" )

  einfo "Checking dependencies: ${args[*]}"
  mapfile -t missing < <(
    /mnt/host/source/chromite/scripts/package_has_missing_deps \
    "${args[@]}"
  )
  if [[ -n "${missing[*]}" ]]; then
    eerror "Missing dependencies were found:"
    for line in "${missing[@]}"; do
      eerror "${line}"
    done
    die "Please correct the missing dependencies."
  fi
fi
