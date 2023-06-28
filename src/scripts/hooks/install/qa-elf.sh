#!/bin/bash

# Copyright (c) 2012 The Chromium OS Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

check_compiler_flags()
{
  # TODO(crbug.com/1061666): We don't build with -frecord-gcc-switches
  # anymore, so these checks don't work. Disable for now, re-enable once
  # rewritten to work with -grecord-gcc-switches.
  return
}

check_linker_flags()
{
  local binary="$1"
  local pie=false
  local relro=false
  local now=false
  ${readelf} -dlSW "${binary}" | \
  {
    while read line ; do
      case "${line}" in
        *"Shared object file"*)
          pie=true
          ;;
        *"GNU_RELRO"*)
          relro=true
          ;;
        *"BIND_NOW"*)
          now=true
          ;;
      esac
    done

    ${pie} || echo "File not PIE: ${binary}"
    ${relro} || echo "File not built with -Wl,-z,relro: ${binary}"
    ${now} || echo "File not built with -Wl,-z,now: ${binary}"
  }
}

check_binaries()
{
  if [[ " ${RESTRICT} " == *" binchecks "* ]] ; then
    return
  fi

  local readelf="llvm-readelf"
  local binary
  scanelf -y -B -F '%F' -R "${D}" | \
    while read binary ; do
      case "${binary}" in
        *.ko)
          ;;
        ${D%/}/usr/lib/debug/*)
          ;;
        *)
          check_compiler_flags "${binary}"
          check_linker_flags "${binary}"
          ;;
      esac
    done
}

check_binaries
