#!/bin/bash

# Copyright 2014 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

source tests-common.sh

inherit appid
inherit hwid

valid_inputs=(
  'SNOW BETA 1'
  'TEST1234'
)

tbegin "no args"
! (dohwid) >&/dev/null
tend $?

tbegin "too many args"
! (dohwid hello 1234 test) >&/dev/null
tend $?

tbegin "missing lsb release file"
for input in "${valid_inputs[@]}"; do
  if (dohwid "${input}") >&/dev/null; then
    tend 1 "added hwid without an lsb release file: ${input}"
  fi
  rm -rf "${D}"
done
tend $?

tbegin "valid inputs"
for input in "${valid_inputs[@]}"; do
  if ! (doappid "{01234567-89AB-CDEF-0123-456789ABCDEF}"); then
    tend 1 "appid could not be created"
  fi
  IUSE="${IUSE} hwid_override"
  if ! (dohwid "$input"); then
    tend 1 "valid input blocked: ${input}"
  fi
  rm -rf "${D}"
done
tend $?

texit
