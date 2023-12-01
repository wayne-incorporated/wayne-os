#!/bin/bash
# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# This script is given one argument: the base of the source directory of
# the package, and it prints a string on stdout with the numerical version
# number for said repo.

# We used to use git tags, but CI doesn't reliably sync them anymore.
# https://crbug.com/1026300

exec "$1"/setup.py --version
