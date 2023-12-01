#!/bin/sh
# Copyright 2016 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Pick the first one that exists.
set -- "$1"/nassh/manifest*.json

exec gawk \
  '$1 == "\"version\":" {print gensub(/[",]/, "", "g", $NF)}' \
  "$1"
