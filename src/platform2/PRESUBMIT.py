# Copyright 2019 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Hook to stop people from running `git cl`."""

import sys


USE_PYTHON3 = True


def CheckChangeOnUpload(_input_api, _output_api):
    print(
        "ERROR: CrOS repos use `repo upload`, not `git cl upload`.",
        file=sys.stderr,
    )
    sys.exit(1)
