#!/bin/bash

# Copyright 2014 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

source tests-common.sh

inherit crashid

valid_inputs=(
	'ChromeOS'
	'version_one-twenty'
	'Chrome.OS'
)

invalid_inputs=(
	'Chromeos12'
	'first!'
	'version_1.20'
	'version 1'
	'Brillo@home'
	'version=1'
)

tbegin "no args"
! (docrashid) >&/dev/null
tend $?

tbegin "too many args"
! (docrashid hello 1234 test) >&/dev/null
tend $?

tbegin "invalid inputs"
for input in "${invalid_inputs[@]}" ; do
	if (docrashid "${input}" "${valid_inputs[0]}") >&/dev/null || \
		(docrashid "${valid_inputs[0]}" "${input}") >&/dev/null ; then
		tend 1 "bad input not caught: ${input}"
	fi
	rm -rf "${D}"
done
tend $?

tbegin "valid inputs"
for input in "${valid_inputs[@]}" ; do
	if ! (docrashid "$input" "${input}") ; then
		tend 1 "valid input blocked: ${input}"
	fi
	rm -rf "${D}"
done
tend $?

tbegin "crash id only"
if ! (docrashid "crash_id" "") ; then
	tend 1 "failed when crash version id is missing"
fi
rm -rf "${D}"
tend $?

texit
