#!/bin/sh
#
# Copyright 2013 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# This script is given one argument: the base of the source directory of
# the package, and it prints a string on stdout with the numerical version
# number for said repo.

# Use the timestamp of the last git commit as our version.
# In practice, it should never go backwards in time ...
stamp=$(git --git-dir="$1/.git" log -n1 --pretty=format:%ci HEAD)
exec date --date="${stamp}" -u "+%Y.%m.%d.%H%M%S"
