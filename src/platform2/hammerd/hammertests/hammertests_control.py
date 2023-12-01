#!/usr/bin/env python3
# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Control file for the following tests

   flash_wrong_address.py
   rb_rw_protected py
   ro_boot_valid_rw.py
   ro_stay_ro.py
   verify_pairing.py
   rw_no_update_ro.py
   ro_update_rw.py
"""

from __future__ import print_function

import os
import shutil
import subprocess
import sys


def main(argv):
    if len(argv) > 0:
        sys.exit("Test takes no args!")
    iterations = 10
    test_list = [
        "verify_pairing",
        "ro_stay_ro",
        "flash_wrong_address",
        "rb_rw_protected",
        "ro_boot_valid_rw",
        "rw_no_update_ro",
        "ro_update_rw",
    ]

    for test in test_list:
        logs_dir = "logs/" + test
        if os.path.exists(logs_dir):
            shutil.rmtree(logs_dir)
        os.makedirs(logs_dir)
        for i in range(iterations):
            iteration_num = i + 1
            print("==========================================================")
            print("TEST NAME: " + test)
            print("ITERATION " + str(iteration_num) + " OF " + str(iterations))
            print("==========================================================")
            cmd = f'set -o pipefail; python3 "{test}.py" 2>&1 '
            cmd += f'| tee "{logs_dir}/{test}{iteration_num}.log"'
            subprocess.check_call(["/bin/bash", "-c", cmd])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
