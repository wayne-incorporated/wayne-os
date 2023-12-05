#!/bin/bash
# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

: "${D:=}"

if [[ -z "${SYSROOT}" ]]; then
  echo "SYSROOT is required" >&2
  exit 1
fi

if [[ ! -f "${SYSROOT}/build/share/constants.json" ]]; then
  echo "SKIPPING: Cannot find constants.json" >&2
  exit 0
fi

shopt -s nullglob
if [[ -n "${D}" ]]; then
  set -- "${D}"/usr/share/policy/*.policy \
    "${D}"/opt/google/touch/policies/*.policy
fi

for policy in "$@"; do
  # TODO(b/267522710) move this over to the seccomp policy linter.
  compile_seccomp_policy \
    --arch-json "${SYSROOT}/build/share/constants.json" \
    --default-action trap "${policy}" /dev/null \
    || die "failed to compile seccomp policy $(basename "${policy}")"
done
