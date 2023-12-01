#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# pylint: disable=module-missing-docstring,class-missing-docstring

import os
import subprocess

import power_manager_prefs_gen_schema  # pylint: disable=import-error

from chromite.lib import cros_test_lib


THIS_DIR = os.path.dirname(__file__)
SCHEMA_FILE = os.path.join(THIS_DIR, "power_manager_prefs_schema.yaml")


class MainTest(cros_test_lib.TempDirTestCase):
    def testSchemaMatches(self):
        output_file = os.path.join(self.tempdir, "output")
        power_manager_prefs_gen_schema.Main(output=output_file)

        changed = (
            subprocess.run(  # pylint: disable=subprocess-run-check
                ["diff", SCHEMA_FILE, output_file]
            ).returncode
            != 0
        )

        if changed:
            print("Please run ./regen.sh in the chromeos-config directory")
            self.fail("Powerd prefs schema does not match C++ prefs source.")


if __name__ == "__main__":
    cros_test_lib.main(module=__name__)
