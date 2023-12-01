#!/bin/sh
#
# Copyright 2012 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# This script is given one argument: the base of the source directory of
# the package, and it prints a string on stdout with the numerical version
# number for said repo.

# The variables at the stop of the U-Boot Makefile are well known and stable
# over many years (e.g. 2013-2017). We can create the version number from this
# information fairly easily without trying to run the Makefile (which does not
# work since the Kconfig conversion).
exec awk '
  {
    if ($1 == "VERSION") {
      version = $3
    } else if ($1 == "PATCHLEVEL") {
      patchlevel = $3
    }
  }
  END { print version "." patchlevel }
' "$1/Makefile"
