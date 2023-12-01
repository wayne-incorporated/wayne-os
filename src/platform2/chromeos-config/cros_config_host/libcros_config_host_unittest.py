#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
# pylint: disable=class-missing-docstring

"""The unit test suite for the libcros_config_host.py library"""

from __future__ import print_function

from collections import OrderedDict
from contextlib import contextmanager
from io import StringIO
import os
import sys
import unittest

# pylint: disable=import-error
from libcros_config_host import CrosConfig
from libcros_config_host_base import BaseFile
from libcros_config_host_base import DeviceSignerInfo
from libcros_config_host_base import FirmwareImage
from libcros_config_host_base import FirmwareInfo
from libcros_config_host_base import SymlinkedFile


# pylint: enable=import-error


YAML_FILE = "../test_data/test.yaml"
MODELS = sorted(["some", "another", "whitelabel"])
ANOTHER_BUCKET = (
    "gs://chromeos-binaries/HOME/bcs-another-private/overlay-"
    "another-private/chromeos-base/chromeos-firmware-another/"
)
SOME_BUCKET = (
    "gs://chromeos-binaries/HOME/bcs-some-private/"
    "overlay-some-private/chromeos-base/chromeos-firmware-some/"
)
SOME_FIRMWARE_FILES = [
    "Some_EC.1111.11.1.tbz2",
    "Some_EC_RW.1111.11.1.tbz2",
    "Some.1111.11.1.tbz2",
    "Some_RW.1111.11.1.tbz2",
]
ANOTHER_FIRMWARE_FILES = [
    "Another_EC.1111.11.1.tbz2",
    "Another.1111.11.1.tbz2",
    "Another_RW.1111.11.1.tbz2",
]

LIB_FIRMWARE = "/lib/firmware/"
TOUCH_FIRMWARE = "/opt/google/touch/firmware/"


# Use this to suppress stdout/stderr output:
# with capture_sys_output() as (stdout, stderr)
#   ...do something...
@contextmanager
def capture_sys_output():
    capture_out, capture_err = StringIO(), StringIO()
    old_out, old_err = sys.stdout, sys.stderr
    try:
        sys.stdout, sys.stderr = capture_out, capture_err
        yield capture_out, capture_err
    finally:
        sys.stdout, sys.stderr = old_out, old_err


class CrosConfigHostTest(unittest.TestCase):
    def setUp(self):
        self.filepath = os.path.join(os.path.dirname(__file__), YAML_FILE)
        self.maxDiff = 80 * 25  # 25 lines

    def assertOrderedDictEqual(self, first, second):
        self.assertListEqual(list(first.items()), list(second.items()))

    def testGetProperty(self):
        config = CrosConfig(self.filepath)
        another = config.GetConfig("another")
        self.assertEqual(another.GetProperty("/", "wallpaper"), "default")
        with self.assertRaises(Exception):
            another.GetProperty("/", "missing")

    def testModels(self):
        config = CrosConfig(self.filepath)
        models = config.GetModelList()
        for model in MODELS:
            self.assertIn(model, models)

    def testGetFirmwareUris(self):
        config = CrosConfig(self.filepath)
        firmware_uris = config.GetConfig("another").GetFirmwareUris()
        self.assertSequenceEqual(
            firmware_uris,
            sorted(
                [ANOTHER_BUCKET + fname for fname in ANOTHER_FIRMWARE_FILES]
            ),
        )

    def testGetSharedFirmwareUris(self):
        config = CrosConfig(self.filepath)
        firmware_uris = config.GetFirmwareUris()
        expected = sorted(
            [ANOTHER_BUCKET + fname for fname in ANOTHER_FIRMWARE_FILES]
            + [SOME_BUCKET + fname for fname in SOME_FIRMWARE_FILES]
        )
        self.assertSequenceEqual(firmware_uris, expected)

    def testGetArcFiles(self):
        config = CrosConfig(self.filepath)
        arc_files = config.GetArcFiles()
        self.assertEqual(
            arc_files,
            [
                BaseFile(
                    source="some/hardware_features.xml",
                    dest="/etc/some_hardware_features.xml",
                ),
                BaseFile(
                    source="some/media_profiles.xml",
                    dest="/etc/some_media_profiles.xml",
                ),
            ],
        )

    def testGetArcCodecFiles(self):
        config = CrosConfig(self.filepath)
        arc_files = config.GetArcCodecFiles()
        self.assertEqual(
            arc_files,
            [
                BaseFile(
                    source="some/media_codecs_c2.xml",
                    dest="/etc/some_media_codecs_c2.xml",
                ),
                BaseFile(
                    source="some/media_codecs_performance_c2.xml",
                    dest="/etc/some_media_codecs_performance_c2.xml",
                ),
            ],
        )

    def testGetThermalFiles(self):
        config = CrosConfig(self.filepath)
        thermal_files = config.GetThermalFiles()
        self.assertEqual(
            thermal_files,
            [
                BaseFile("another/dptf.dv", "/etc/dptf/another/dptf.dv"),
                BaseFile(
                    "some_notouch/dptf.dv", "/etc/dptf/some_notouch/dptf.dv"
                ),
                BaseFile("some_touch/dptf.dv", "/etc/dptf/some_touch/dptf.dv"),
            ],
        )

    def testGetFirmwareBuildTargets(self):
        config = CrosConfig(self.filepath)
        self.assertSequenceEqual(
            config.GetFirmwareBuildTargets("coreboot"),
            ["another", "badrecovery1", "badrecovery2", "some"],
        )
        os.environ["FW_NAME"] = "another"
        self.assertSequenceEqual(
            config.GetFirmwareBuildTargets("coreboot"), ["another"]
        )
        self.assertSequenceEqual(
            config.GetFirmwareBuildTargets("ec"),
            ["another", "another_base", "extra1", "extra2"],
        )
        del os.environ["FW_NAME"]

    def testGetProximitySensorFiles(self):
        config = CrosConfig(self.filepath)
        proximity_files = config.GetProximitySensorFiles()
        self.assertEqual(
            proximity_files,
            [
                BaseFile(
                    "build_path/config_project_left.json",
                    "/usr/share/chromeos-assets/proximity-sensor/wifi/"
                    "config_project_left.json",
                ),
                BaseFile(
                    "build_path/config_project_right.json",
                    "/usr/share/chromeos-assets/proximity-sensor/wifi/"
                    "config_project_right.json",
                ),
            ],
        )

    def testFileTree(self):
        """Test that we can obtain a file tree"""
        config = CrosConfig(self.filepath)
        node = config.GetFileTree()
        self.assertEqual(node.name, "")
        self.assertEqual(
            sorted(node.children.keys()), ["etc", "lib", "opt", "usr"]
        )
        etc = node.children["etc"]
        self.assertEqual(etc.name, "etc")
        cras = etc.children["cras"]
        self.assertEqual(cras.name, "cras")
        another = cras.children["another"]
        self.assertEqual(sorted(another.children.keys()), ["a-card", "dsp.ini"])

    def testShowTree(self):
        """Test that we can show a file tree"""
        config = CrosConfig(self.filepath)
        tree = config.GetFileTree()
        with capture_sys_output() as (stdout, stderr):
            config.ShowTree("/", tree)
        self.assertEqual(stderr.getvalue(), "")
        lines = [line.strip() for line in stdout.getvalue().splitlines()]
        self.assertEqual(lines[0].split(), ["Size", "Path"])
        self.assertEqual(lines[1], "/")
        self.assertEqual(lines[2], "etc/")
        self.assertEqual(lines[3].split(), ["missing", "cras/"])

    def testFirmwareBuildCombinations(self):
        """Test generating a dict of firmware build combinations."""
        config = CrosConfig(self.filepath)
        expected = OrderedDict(
            [
                ("another", ["another", "another"]),
                ("badrecovery1", ["badrecovery1", "badrecovery1"]),
                ("badrecovery2", ["badrecovery2", "badrecovery2"]),
                ("some", ["some", "some"]),
                ("some2", [None, None]),
                ("some2_custom", [None, None]),
            ]
        )
        result = config.GetFirmwareBuildCombinations(
            ["coreboot", "depthcharge"]
        )
        self.assertEqual(result, expected)

        # Unspecified targets should be represented as None.
        expected = OrderedDict(
            [
                ("another", ["some/another"]),
                ("badrecovery1", [None]),
                ("badrecovery2", [None]),
                ("some", [None]),
                ("some2", ["experimental/some2"]),
                ("some2_custom", ["experimental/some2"]),
            ]
        )
        result = config.GetFirmwareBuildCombinations(["zephyr-ec"])
        self.assertEqual(result, expected)

        os.environ["FW_NAME"] = "another"
        expected = OrderedDict([("another", ["another", "another"])])
        result = config.GetFirmwareBuildCombinations(
            ["coreboot", "depthcharge"]
        )
        self.assertEqual(result, expected)
        del os.environ["FW_NAME"]

    def testFirmwareRecoveryInput(self):
        """Test querying and generating recovery-input modes"""
        config = CrosConfig(self.filepath)
        # Use test config with recovery-input set to KEYBOARD
        expected = "KEYBOARD"
        result = config.GetFirmwareRecoveryInput("depthcharge", "another")
        self.assertEqual(result, expected)

        # Use test config with recovery-input set to POWER_BUTTON
        # Manually set recovery-input differs from auto generate option
        expected = "POWER_BUTTON"
        result = config.GetFirmwareRecoveryInput(
            "zephyr-ec", "experimental/some2"
        )
        self.assertEqual(result, expected)

        # Use test config with form-factor set to CHROMEBOX
        # and no recovery-input set (to generate it)
        expected = "RECOVERY_BUTTON"
        result = config.GetFirmwareRecoveryInput("depthcharge", "some")
        self.assertEqual(result, expected)

        # Test a clash in the specified recovery inputs
        with self.assertRaises(Exception):
            config.GetFirmwareRecoveryInput("depthcharge", "badrecovery1")

        # Test a clash in the auto generated recovery inputs
        with self.assertRaises(Exception):
            config.GetFirmwareRecoveryInput("depthcharge", "badrecovery2")

    def testKeyValuePair(self):
        """Test querying for a set of key-value pairs"""
        config = CrosConfig(self.filepath)
        expected = {
            "some": "bloonchipper",
            "some2": "bloonchipper",
            "another": "dartmonkey",
            "some_customization": "bloonchipper",
            "whitelabel": "bloonchipper",
            "badrecovery1": "bloonchipper",
            "badrecovery2": "bloonchipper",
            "multi": "bloonchipper",
        }
        result = config.GetKeyValuePairs("/", "name", "/fingerprint", "board")
        self.assertEqual(expected, result)

        # Test a clash in key-value pairs
        with self.assertRaises(Exception):
            config.GetKeyValuePairs("/", "name", "/firmware", "image-name")

    def testKeyValue(self):
        """Test querying a particular key-value pair by key"""
        config = CrosConfig(self.filepath)
        expected = "bloonchipper"
        result = config.GetKeyValue(
            key_path="/",
            key_name="name",
            key_match="some",
            value_path="/fingerprint",
            value_name="board",
        )
        self.assertEqual(expected, result)

        # Test ignore-unset option
        expected = "True"
        result = config.GetKeyValue(
            key_path="/",
            key_name="name",
            key_match="some",
            value_path="/hardware-properties",
            value_name="has-base-accelerometer",
            ignore_unset=True,
        )
        self.assertEqual(expected, result)

        # Test a clash in key-value pairs
        with self.assertRaises(Exception):
            config.GetKeyValue("/", "name", "/firmware", "image-name")

    def testGetWallpaper(self):
        """Test that we can access the wallpaper information"""
        config = CrosConfig(self.filepath)
        wallpaper = config.GetWallpaperFiles()
        self.assertEqual(
            ["default", "some", "wallpaper-wl1", "wallpaper-wl2"], wallpaper
        )

    def testGetTouchFirmwareFiles(self):
        def _GetFile(source, symlink):
            """Helper to return a suitable SymlinkedFile"""
            return SymlinkedFile(
                source, TOUCH_FIRMWARE + source, LIB_FIRMWARE + symlink
            )

        config = CrosConfig(self.filepath)
        touch_files = config.GetConfig("another").GetTouchFirmwareFiles()
        # pylint: disable=line-too-long
        self.assertEqual(
            touch_files,
            [
                SymlinkedFile(
                    source="some_stylus_vendor/another-version.hex",
                    dest="/opt/google/touch/firmware/some_stylus_vendor/another-version.hex",
                    symlink="/lib/firmware/some_stylus_vendor_firmware_ANOTHER.bin",
                ),
                SymlinkedFile(
                    source="some_touch_vendor/some-pid_some-version.bin",
                    dest="/opt/google/touch/firmware/some_touch_vendor/some-pid_some-version.bin",
                    symlink="/lib/firmware/some_touch_vendorts_i2c_some-pid.bin",
                ),
            ],
        )
        touch_files = config.GetConfig("some").GetTouchFirmwareFiles()

        # This checks that duplicate processing works correct, since both models
        # have the same wacom firmware
        self.assertEqual(
            touch_files,
            [
                SymlinkedFile(
                    source="some_stylus_vendor/some-version.hex",
                    dest="/opt/google/touch/firmware/some_stylus_vendor/some-version.hex",
                    symlink="/lib/firmware/some_stylus_vendor_firmware_SOME.bin",
                ),
                SymlinkedFile(
                    source="some_touch_vendor/some-pid_some-version.bin",
                    dest="/opt/google/touch/firmware/some_touch_vendor/some-pid_some-version.bin",
                    symlink="/lib/firmware/some_touch_vendorts_i2c_some-pid.bin",
                ),
                SymlinkedFile(
                    source="some_touch_vendor/some-other-pid_some-other-version.bin",
                    dest="/opt/google/touch/firmware/some_touch_vendor/some-other-pid_some-other-version.bin",
                    symlink="/lib/firmware/some_touch_vendorts_i2c_some-other-pid.bin",
                ),
            ],
        )
        touch_files = config.GetTouchFirmwareFiles()
        expected = set(
            [
                SymlinkedFile(
                    source="some_stylus_vendor/another-version.hex",
                    dest="/opt/google/touch/firmware/some_stylus_vendor/another-version.hex",
                    symlink="/lib/firmware/some_stylus_vendor_firmware_ANOTHER.bin",
                ),
                SymlinkedFile(
                    source="some_stylus_vendor/some-version.hex",
                    dest="/opt/google/touch/firmware/some_stylus_vendor/some-version.hex",
                    symlink="/lib/firmware/some_stylus_vendor_firmware_SOME.bin",
                ),
                SymlinkedFile(
                    source="some_touch_vendor/some-pid_some-version.bin",
                    dest="/opt/google/touch/firmware/some_touch_vendor/some-pid_some-version.bin",
                    symlink="/lib/firmware/some_touch_vendorts_i2c_some-pid.bin",
                ),
                SymlinkedFile(
                    source="some_touch_vendor/some-other-pid_some-other-version.bin",
                    dest="/opt/google/touch/firmware/some_touch_vendor/some-other-pid_some-other-version.bin",
                    symlink="/lib/firmware/some_touch_vendorts_i2c_some-other-pid.bin",
                ),
                SymlinkedFile(
                    source="some_touch_vendor/some-pid_some-version.bin",
                    dest="/opt/google/touch/firmware/some_touch_vendor/some-pid_some-version.bin",
                    symlink="/lib/firmware/some_touch_vendorts_i2c_some-pid.bin",
                ),
            ]
        )
        self.assertEqual(set(touch_files), expected)

    def testGetAudioFiles(self):
        config = CrosConfig(self.filepath)
        audio_files = config.GetAudioFiles()
        expected = [
            BaseFile(
                source="cras-config/another/dsp.ini",
                dest="/etc/cras/another/dsp.ini",
            ),
            BaseFile(
                source="cras-config/another/a-card",
                dest="/etc/cras/another/a-card",
            ),
            BaseFile(
                source="cras-config/some/dsp.ini", dest="/etc/cras/some/dsp.ini"
            ),
            BaseFile(
                source="cras-config/some/a-card", dest="/etc/cras/some/a-card"
            ),
            BaseFile(
                source="cras-config/some2/dsp.ini",
                dest="/etc/cras/some2/dsp.ini",
            ),
            BaseFile(
                source="cras-config/some2/a-card", dest="/etc/cras/some2/a-card"
            ),
            BaseFile(
                source="topology/another-tplg.bin",
                dest="/lib/firmware/another-tplg.bin",
            ),
            BaseFile(
                source="topology/some-tplg.bin",
                dest="/lib/firmware/some-tplg.bin",
            ),
            BaseFile(
                source="ucm-config/a-card.another/HiFi.conf",
                dest="/usr/share/alsa/ucm/a-card.another/HiFi.conf",
            ),
            BaseFile(
                source="ucm-config/a-card.another/a-card.another.conf",
                dest="/usr/share/alsa/ucm/a-card.another/a-card.another.conf",
            ),
            BaseFile(
                source="ucm-config/a-card.some/HiFi.conf",
                dest="/usr/share/alsa/ucm/a-card.some/HiFi.conf",
            ),
            BaseFile(
                source="ucm-config/a-card.some/a-card.some.conf",
                dest="/usr/share/alsa/ucm/a-card.some/a-card.some.conf",
            ),
            BaseFile(
                source="ucm-config/a-card.some2/HiFi.conf",
                dest="/usr/share/alsa/ucm/a-card.some2/HiFi.conf",
            ),
            BaseFile(
                source="ucm-config/a-card.some2/a-card.some2.conf",
                dest="/usr/share/alsa/ucm/a-card.some2/a-card.some2.conf",
            ),
        ]

        self.assertEqual(audio_files, sorted(expected))

    def testFirmware(self):
        """Test access to firmware information"""
        expected = OrderedDict(
            [
                (
                    "another",
                    FirmwareInfo(
                        model="another",
                        shared_model="another",
                        key_id="ANOTHER",
                        have_image=True,
                        bios_build_target="another",
                        ec_build_target="another",
                        main_image_uri="bcs://Another.1111.11.1.tbz2",
                        main_rw_image_uri="bcs://Another_RW.1111.11.1.tbz2",
                        ec_image_uri="bcs://Another_EC.1111.11.1.tbz2",
                        ec_rw_image_uri="",
                        pd_image_uri="",
                        sig_id="another",
                        brand_code="",
                    ),
                ),
                (
                    "badrecovery1",
                    FirmwareInfo(
                        model="badrecovery1",
                        shared_model="badrecovery1",
                        key_id=None,
                        have_image=True,
                        bios_build_target="badrecovery1",
                        ec_build_target="badrecovery1",
                        main_image_uri="",
                        main_rw_image_uri="",
                        ec_image_uri="",
                        ec_rw_image_uri="",
                        pd_image_uri="",
                        sig_id=None,
                        brand_code="",
                    ),
                ),
                (
                    "badrecovery2",
                    FirmwareInfo(
                        model="badrecovery2",
                        shared_model="badrecovery2",
                        key_id=None,
                        have_image=True,
                        bios_build_target="badrecovery2",
                        ec_build_target="badrecovery2",
                        main_image_uri="",
                        main_rw_image_uri="",
                        ec_image_uri="",
                        ec_rw_image_uri="",
                        pd_image_uri="",
                        sig_id=None,
                        brand_code="",
                    ),
                ),
                (
                    "multi",
                    FirmwareInfo(
                        model="multi",
                        shared_model="multi",
                        key_id="WHITELABEL1",
                        have_image=True,
                        bios_build_target=None,
                        ec_build_target=None,
                        main_image_uri="",
                        main_rw_image_uri="",
                        ec_image_uri="",
                        ec_rw_image_uri="",
                        pd_image_uri="",
                        sig_id="sig-id-in-customization-id",
                        brand_code="",
                    ),
                ),
                (
                    "multi-whitelabel1",
                    FirmwareInfo(
                        model="multi-whitelabel1",
                        shared_model="multi",
                        key_id="WHITELABEL1",
                        have_image=False,
                        bios_build_target=None,
                        ec_build_target=None,
                        main_image_uri="",
                        main_rw_image_uri="",
                        ec_image_uri="",
                        ec_rw_image_uri="",
                        pd_image_uri="",
                        sig_id="multi-whitelabel1",
                        brand_code="WLBA",
                    ),
                ),
                (
                    "multi_other",
                    FirmwareInfo(
                        model="multi_other",
                        shared_model="multi_other",
                        key_id="WHITELABEL1",
                        have_image=True,
                        bios_build_target=None,
                        ec_build_target=None,
                        main_image_uri="",
                        main_rw_image_uri="",
                        ec_image_uri="",
                        ec_rw_image_uri="",
                        pd_image_uri="",
                        sig_id="sig-id-in-customization-id",
                        brand_code="",
                    ),
                ),
                (
                    "multi_other-whitelabel1",
                    FirmwareInfo(
                        model="multi_other-whitelabel1",
                        shared_model="multi_other",
                        key_id="WHITELABEL1",
                        have_image=False,
                        bios_build_target=None,
                        ec_build_target=None,
                        main_image_uri="",
                        main_rw_image_uri="",
                        ec_image_uri="",
                        ec_rw_image_uri="",
                        pd_image_uri="",
                        sig_id="multi_other-whitelabel1",
                        brand_code="WLBA",
                    ),
                ),
                (
                    "multi-whitelabel2",
                    FirmwareInfo(
                        model="multi-whitelabel2",
                        shared_model="multi",
                        key_id="WHITELABEL2",
                        have_image=False,
                        bios_build_target=None,
                        ec_build_target=None,
                        main_image_uri="",
                        main_rw_image_uri="",
                        ec_image_uri="",
                        ec_rw_image_uri="",
                        pd_image_uri="",
                        sig_id="multi-whitelabel2",
                        brand_code="WLBB",
                    ),
                ),
                (
                    "multi_other-whitelabel2",
                    FirmwareInfo(
                        model="multi_other-whitelabel2",
                        shared_model="multi_other",
                        key_id="WHITELABEL2",
                        have_image=False,
                        bios_build_target=None,
                        ec_build_target=None,
                        main_image_uri="",
                        main_rw_image_uri="",
                        ec_image_uri="",
                        ec_rw_image_uri="",
                        pd_image_uri="",
                        sig_id="multi_other-whitelabel2",
                        brand_code="WLBB",
                    ),
                ),
                (
                    "some",
                    FirmwareInfo(
                        model="some",
                        shared_model="some",
                        key_id="SOME",
                        have_image=True,
                        bios_build_target="some",
                        ec_build_target="some",
                        main_image_uri="bcs://Some.1111.11.1.tbz2",
                        main_rw_image_uri="bcs://Some_RW.1111.11.1.tbz2",
                        ec_image_uri="bcs://Some_EC.1111.11.1.tbz2",
                        ec_rw_image_uri="bcs://Some_EC_RW.1111.11.1.tbz2",
                        pd_image_uri="",
                        sig_id="some",
                        brand_code="",
                    ),
                ),
                (
                    "some2",
                    FirmwareInfo(
                        model="some2",
                        shared_model="some2",
                        key_id="SOME",
                        have_image=True,
                        bios_build_target=None,
                        ec_build_target="experimental/some2",
                        main_image_uri="",
                        main_rw_image_uri="",
                        ec_image_uri="",
                        ec_rw_image_uri="",
                        pd_image_uri="",
                        sig_id="some2",
                        brand_code="",
                    ),
                ),
                (
                    "some2_custom",
                    FirmwareInfo(
                        model="some2_custom",
                        shared_model="some2_custom",
                        key_id="SOME",
                        have_image=True,
                        bios_build_target=None,
                        ec_build_target="experimental/some2",
                        main_image_uri="",
                        main_rw_image_uri="",
                        ec_image_uri="",
                        ec_rw_image_uri="",
                        pd_image_uri="",
                        sig_id="some2",
                        brand_code="",
                    ),
                ),
                (
                    "whitelabel",
                    FirmwareInfo(
                        model="whitelabel",
                        shared_model="some",
                        key_id="WHITELABEL1",
                        have_image=True,
                        bios_build_target="some",
                        ec_build_target="some",
                        main_image_uri="bcs://Some.1111.11.1.tbz2",
                        main_rw_image_uri="bcs://Some_RW.1111.11.1.tbz2",
                        ec_image_uri="bcs://Some_EC.1111.11.1.tbz2",
                        ec_rw_image_uri="bcs://Some_EC_RW.1111.11.1.tbz2",
                        pd_image_uri="",
                        sig_id="sig-id-in-customization-id",
                        brand_code="",
                    ),
                ),
                (
                    "whitelabel-whitelabel1",
                    FirmwareInfo(
                        model="whitelabel-whitelabel1",
                        shared_model="some",
                        key_id="WHITELABEL1",
                        have_image=False,
                        bios_build_target="some",
                        ec_build_target="some",
                        main_image_uri="bcs://Some.1111.11.1.tbz2",
                        main_rw_image_uri="bcs://Some_RW.1111.11.1.tbz2",
                        ec_image_uri="bcs://Some_EC.1111.11.1.tbz2",
                        ec_rw_image_uri="bcs://Some_EC_RW.1111.11.1.tbz2",
                        pd_image_uri="",
                        sig_id="whitelabel-whitelabel1",
                        brand_code="WLBA",
                    ),
                ),
                (
                    "whitelabel-whitelabel2",
                    FirmwareInfo(
                        model="whitelabel-whitelabel2",
                        shared_model="some",
                        key_id="WHITELABEL2",
                        have_image=False,
                        bios_build_target="some",
                        ec_build_target="some",
                        main_image_uri="bcs://Some.1111.11.1.tbz2",
                        main_rw_image_uri="bcs://Some_RW.1111.11.1.tbz2",
                        ec_image_uri="bcs://Some_EC.1111.11.1.tbz2",
                        ec_rw_image_uri="bcs://Some_EC_RW.1111.11.1.tbz2",
                        pd_image_uri="",
                        sig_id="whitelabel-whitelabel2",
                        brand_code="WLBB",
                    ),
                ),
            ]
        )
        result = CrosConfig(self.filepath).GetFirmwareInfo()
        self.assertOrderedDictEqual(result, expected)

    def testFirmwareConfigs(self):
        """Test access to firmware configs."""
        expected = {
            "some": [
                FirmwareImage(
                    type="ap",
                    build_target="some",
                    image_uri="bcs://Some.1111.11.1.tbz2",
                ),
                FirmwareImage(
                    type="ap_rw",
                    build_target="some",
                    image_uri="bcs://Some_RW.1111.11.1.tbz2",
                ),
                FirmwareImage(
                    type="ec",
                    build_target="some",
                    image_uri="bcs://Some_EC.1111.11.1.tbz2",
                ),
                FirmwareImage(
                    type="ec_rw",
                    build_target="some",
                    image_uri="bcs://Some_EC_RW.1111.11.1.tbz2",
                ),
            ],
            "badrecovery1": [],
            "badrecovery2": [],
            "another": [
                FirmwareImage(
                    type="ap",
                    build_target="another",
                    image_uri="bcs://Another.1111.11.1.tbz2",
                ),
                FirmwareImage(
                    type="ap_rw",
                    build_target="another",
                    image_uri="bcs://Another_RW.1111.11.1.tbz2",
                ),
                FirmwareImage(
                    type="ec",
                    build_target="another",
                    image_uri="bcs://Another_EC.1111.11.1.tbz2",
                ),
            ],
            "some2": [],
            "some2_custom": [],
            "multi": [],
            "multi_other": [],
        }

        result = CrosConfig(self.filepath).GetFirmwareConfigs()
        self.assertEqual(result, expected)

    def testFirmwareConfigsByDevice(self):
        """Test access to firmware config names."""
        expected = {
            "some": "some",
            "some2": "some2",
            "some2_custom": "some2_custom",
            "another": "another",
            "whitelabel": "some",
            "whitelabel-whitelabel1": "some",
            "whitelabel-whitelabel2": "some",
            "badrecovery1": "badrecovery1",
            "badrecovery2": "badrecovery2",
            "multi": "multi",
            "multi-whitelabel1": "multi",
            "multi-whitelabel2": "multi",
            "multi_other": "multi_other",
            "multi_other-whitelabel1": "multi_other",
            "multi_other-whitelabel2": "multi_other",
        }

        result = CrosConfig(self.filepath).GetFirmwareConfigsByDevice()
        self.assertEqual(result, expected)

    def testSignerInfoByDevice(self):
        """Test access to device signer info."""
        expected = {
            "whitelabel-whitelabel2": DeviceSignerInfo(
                key_id="WHITELABEL2", sig_id="whitelabel-whitelabel2"
            ),
            "whitelabel-whitelabel1": DeviceSignerInfo(
                key_id="WHITELABEL1", sig_id="whitelabel-whitelabel1"
            ),
            "some": DeviceSignerInfo(key_id="SOME", sig_id="some"),
            "some2": DeviceSignerInfo(key_id="SOME", sig_id="some2"),
            "some2_custom": DeviceSignerInfo(key_id="SOME", sig_id="some2"),
            "whitelabel": DeviceSignerInfo(
                key_id="WHITELABEL1", sig_id="sig-id-in-customization-id"
            ),
            "another": DeviceSignerInfo(key_id="ANOTHER", sig_id="another"),
            "multi": DeviceSignerInfo(
                key_id="WHITELABEL1", sig_id="sig-id-in-customization-id"
            ),
            "multi_other": DeviceSignerInfo(
                key_id="WHITELABEL1", sig_id="sig-id-in-customization-id"
            ),
            "multi-whitelabel1": DeviceSignerInfo(
                key_id="WHITELABEL1", sig_id="multi-whitelabel1"
            ),
            "multi_other-whitelabel1": DeviceSignerInfo(
                key_id="WHITELABEL1", sig_id="multi_other-whitelabel1"
            ),
            "multi-whitelabel2": DeviceSignerInfo(
                key_id="WHITELABEL2", sig_id="multi-whitelabel2"
            ),
            "multi_other-whitelabel2": DeviceSignerInfo(
                key_id="WHITELABEL2", sig_id="multi_other-whitelabel2"
            ),
        }

        result = CrosConfig(self.filepath).GetDeviceSignerInfo()
        self.assertEqual(result, expected)


if __name__ == "__main__":
    unittest.main()
