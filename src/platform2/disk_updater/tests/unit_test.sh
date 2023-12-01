#!/bin/bash
# Copyright 2014 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# Command for unit test.
echo "$(basename "$0")" "$@" | sed -E "s#/tmp/test_fw\..{6}#temp_dir#g"
case "$@" in
  *--action=2) exit 11;;
  *) exit 0;;
esac
