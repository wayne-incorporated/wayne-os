#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""The unit test suite for the CrosConfigHost CLI tool."""

from __future__ import print_function

import os
import subprocess
import sys
import unittest


YAML_FILE = "../test_data/test.yaml"


class CrosConfigHostTest(unittest.TestCase):
    """Tests for model configuration in yaml format"""

    def setUp(self):
        self.conf_file = os.path.join(os.path.dirname(__file__), YAML_FILE)

    # Common tests shared between the YAML and FDT implementations.
    def CheckManyLinesWithoutSpaces(self, output, lines=3):
        # Expect there to be a few lines
        self.assertGreater(len(output.split()), lines)
        # Expect each line to not have spaces in it
        for line in output.split():
            self.assertFalse(" " in line)
            self.assertNotEqual(line[-1:], " ")
        # Expect the last thing in the output to be a newline
        self.assertEqual(output[-1:], os.linesep)

    def CheckManyLines(self, output, lines=3):
        # Expect there to be a few lines
        self.assertGreater(len(output.split()), lines)
        # Expect each line to not end in space
        for line in output.split():
            self.assertNotEqual(line[-1:], " ")
        # Expect the last thing in the output to be a newline
        self.assertEqual(output[-1:], os.linesep)

    def _call_args(self, *args, **kwargs):
        call_args = [
            sys.executable,
            "-m",
            "cros_config_host.cros_config_host",
            "-c",
            self.conf_file,
        ]
        model = kwargs.pop("model", None)
        if model:
            call_args.extend(["--model", model])
        call_args.extend(args)
        return call_args, kwargs

    def _check_output(self, *args, **kwargs):
        call_args, kwargs = self._call_args(*args, **kwargs)
        return subprocess.run(
            call_args,
            encoding="utf-8",
            check=True,
            stdout=subprocess.PIPE,
            **kwargs,
        ).stdout

    def testListModels(self):
        output = self._check_output("list-models")
        self.CheckManyLinesWithoutSpaces(output, lines=2)

    def testListModelsWithFilter(self):
        output = self._check_output("list-models", model="another")
        self.assertEqual("another\n", output)

    def testListModelsWithEnvFilter(self):
        os.environ["CROS_CONFIG_MODEL"] = "another"
        output = self._check_output("list-models")
        del os.environ["CROS_CONFIG_MODEL"]
        self.assertEqual("another\n", output)

    def testGetPropSingle(self):
        output = self._check_output("get", "/", "wallpaper", model="another")
        self.assertEqual(output, "default" + os.linesep)

    def testGetPropSingleWrongModel(self):
        output = self._check_output(
            "get", "/", "wallpaper", model="dne", stderr=subprocess.PIPE
        )
        self.assertEqual(output, "")

    def testGetPropSingleWrongPath(self):
        with self.assertRaises(subprocess.CalledProcessError):
            self._check_output(
                "get",
                "/dne",
                "wallpaper",
                model="another",
                stderr=subprocess.DEVNULL,
            )

    def testGetPropSingleWrongProp(self):
        with self.assertRaises(subprocess.CalledProcessError):
            self._check_output(
                "get", "/", "dne", model="another", stderr=subprocess.DEVNULL
            )

    def testGetFirmwareUris(self):
        output = self._check_output("get-firmware-uris")
        self.CheckManyLines(output)

    def testGetFingerprintFirmwareROVersionFound(self):
        output = self._check_output(
            "get-fpmcu-firmware-ro-version", "bloonchipper"
        )
        self.assertEqual(output, "VERSION1\n")

    def testGetFingerprintFirmwareROVersionNotSpecified(self):
        # If the ro-version is not specified, nothing is returned and the exit
        # code should be 0.
        output = self._check_output(
            "get-fpmcu-firmware-ro-version", "some_fpmcu"
        )
        self.assertEqual(output, "")

    def testGetTouchFirmwareFiles(self):
        output = self._check_output("get-touch-firmware-files")
        self.CheckManyLines(output, 10)

    def testGetAudioFiles(self):
        output = self._check_output("get-audio-files")
        self.CheckManyLines(output, 10)

    def testGetFirmwareBuildTargets(self):
        output = self._check_output("get-firmware-build-targets", "coreboot")
        self.CheckManyLines(output, 1)

    def testGetWallpaperFiles(self):
        output = self._check_output("get-wallpaper-files")
        self.CheckManyLines(output, 1)

    def testGetIntelWifiSarFiles(self):
        output = self._check_output("get-intel-wifi-sar-files")
        self.CheckManyLines(output, 1)

    def testGetProximitySensorFiles(self):
        output = self._check_output("get-proximity-sensor-files")
        self.CheckManyLines(output, 1)


if __name__ == "__main__":
    unittest.main()
