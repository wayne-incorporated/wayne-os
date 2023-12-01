#!/bin/bash
# Copyright 2015 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

source tests-common.sh

EAPI=4

inherit cros-board

tbegin "no board defined"
	name=$(IUSE="" get_current_board_with_variant)
	if [[ -n "${name}" ]]; then
		tend 1 "should return nothing when no board or default is defined"
	fi
tend $?

tbegin "no board defined with default"
	name=$(IUSE="" get_current_board_with_variant "default")
	if [[ "${name}" != "default" ]]; then
		tend 1 "should return the default when provided and the board isn't set"
	fi
tend $?

tbegin "board defined with default"
	name=$(IUSE="board_use_link" get_current_board_with_variant "default")
	if [[ "${name}" != "link" ]]; then
		tend 1 "should use board when provided"
	fi
tend $?

tbegin "two boards defined"
	if (IUSE="board_use_link board_use_daisy" \
		get_current_board_with_variant) &>/dev/null; then
		tend 1 "should fail when two boards are set"
	fi
tend $?

texit
