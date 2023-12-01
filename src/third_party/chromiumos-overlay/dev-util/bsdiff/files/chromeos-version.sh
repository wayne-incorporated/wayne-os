#!/bin/sh
# Copyright 2015 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
exec awk '$1 == "Version:" {print $2}' "$2"/README.chromium
