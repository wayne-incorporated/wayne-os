#!/bin/bash

# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
sed -E "s/(CROS_DISKS_OPTS=')/\1--no_session_manager /" "$1" > "$2"
