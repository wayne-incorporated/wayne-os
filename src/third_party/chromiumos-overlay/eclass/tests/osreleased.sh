#!/bin/bash

# Copyright 2014 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

source tests-common.sh

inherit osreleased

# Tests for do_osrelease_field
valid_names=(
	'GOOGLE_METRICS_ID'
	'THIS_IS_A_TEST'
)

invalid_names=(
	'this_is_not_valid'
	'THIS/IS/NOT/VALID/EITHER'
	'NOT THIS EITHER'
	'OR \nTHIS'
	'OR=THIS'
)

invalid_values=(
	'this is
not valid'
)


tbegin "do_osrelease_field: no args"
! (do_osrelease_field) >&/dev/null
tend $?

tbegin "do_osrelease_field: too many args"
! (do_osrelease_field HELLO 1234 test) >&/dev/null
tend $?

tbegin "do_osrelease_field: invalid names"
for input in "${invalid_names[@]}" ; do
	if (do_osrelease_field "${input}" "value") >&/dev/null ; then
		tend 1 "bad input not caught: ${input}"
	fi
	rm -rf "${D}"
done
tend $?

tbegin "do_osrelease_field: invalid values"
for input in "${invalid_values[@]}" ; do
	if (do_osrelease_field "NAME" "${input}") >&/dev/null ; then
		tend 1 "bad input not caught: ${input}"
	fi
	rm -rf "${D}"
done
tend $?

tbegin "do_osrelease_field: valid names"
for input in "${valid_names[@]}" ; do
	if ! (do_osrelease_field "$input" "value") ; then
		tend 1 "valid input blocked: ${input}"
	fi
	rm -rf "${D}"
done
tend $?

# Tests for dometricsproductid.
valid_productid=(
	'12'
	'0'
)

invalid_productid=(
	'not valid'
	'-10'
	'10,000'
)


tbegin "dometricsproductid: no args"
! (dometricsproductid) >&/dev/null
tend $?

tbegin "dometricsproductid: too many args"
! (dometricsproductid 1234 12) >&/dev/null
tend $?

tbegin "dometricsproductid: valid product id"
for input in "${valid_productid[@]}" ; do
	if ! (dometricsproductid "$input") ; then
		tend 1 "valid productid blocked: ${input}"
	fi
	rm -rf "${D}"
done
tend $?

tbegin "dometricsproductid: invalid product id"
for input in "${invalid_productid[@]}" ; do
	if (dometricsproductid "${input}") >&/dev/null ; then
		tend 1 "bad product id not caught: ${input}"
	fi
	rm -rf "${D}"
done
tend $?

texit
