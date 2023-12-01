#!/bin/sh
#
# Copyright 2019 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# This script is given one argument: the base of the source directory of
# the package, and it prints a string on stdout with the numerical version
# number for said repo.

# $1 inside single quotes for awk is intentional.
# shellcheck disable=2016
exec awk '$1 == "Version:" {print $NF}' "$1/ShellCheck.cabal"
