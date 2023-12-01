#!/bin/bash
# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Script to run all Python unit tests in cros_config.

# Exit immediately if a command exits with a non-zero status.
set -e

# Switch to script directory to constrain testing.
cd "$(dirname "$(realpath -e "${BASH_SOURCE[0]}")")"

python3 -m unittest discover -p '*test.py' -v

for unittest in scripts/*_unittest.sh; do
    bash "${unittest}"
done

# Run linter
# TODO(https://crbug.com/1101555): "cros lint" doesn't work when run as part of
# an ebuild.
if which cros; then
    find . -name '*.py' -exec cros lint {} +
fi
