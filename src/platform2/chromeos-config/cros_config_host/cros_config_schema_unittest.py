#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# pylint: disable=module-missing-docstring,class-missing-docstring

import contextlib
import io
import json
import os
import re

# pylint: disable=import-error
import cros_config_schema
import jsonschema
import libcros_schema
from packaging import version
from six.moves import zip_longest

from chromite.lib import cros_test_lib


# pylint: enable=import-error


this_dir = os.path.dirname(__file__)

BASIC_CONFIG = """
reef-9042-fw: &reef-9042-fw
  bcs-overlay: 'overlay-reef-private'
  ec-ro-image: 'Reef_EC.9042.87.1.tbz2'
  main-ro-image: 'Reef.9042.87.1.tbz2'
  main-rw-image: 'Reef.9042.110.0.tbz2'
  build-targets:
    coreboot: 'reef'

chromeos:
  devices:
    - $name: 'basking'
      products:
        - $key-id: 'OEM2'
          $brand-code: 'ASUN'
      skus:
        - $sku-id: 0
          config:
            audio:
              main:
                $card: 'bxtda7219max'
                cras-config-dir: '{{$name}}'
                ucm-suffix: '{{$name}}'
                files:
                  - source: "{{$dsp-ini}}"
                    destination: "/etc/cras/{{$dsp-ini}}"
                    $dsp-ini: "{{cras-config-dir}}/dsp.ini"
            brand-code: '{{$brand-code}}'
            identity:
              platform-name: "Reef"
              frid: "Google_Reef"
              sku-id: "{{$sku-id}}"
            name: '{{$name}}'
            firmware: *reef-9042-fw
            firmware-signing:
              key-id: '{{$key-id}}'
              signature-id: '{{$name}}'
            test-label: 'reef'
"""


class MergeDictionaries(cros_test_lib.TestCase):
    def testBaseKeyMerge(self):
        primary = {"a": {"b": 1, "c": 2}}
        overlay = {"a": {"c": 3}, "b": 4}
        cros_config_schema.MergeDictionaries(primary, overlay)
        self.assertEqual({"a": {"b": 1, "c": 3}, "b": 4}, primary)

    def testBaseListAppend(self):
        primary = {"a": {"b": 1, "c": [1, 2]}}
        overlay = {"a": {"c": [3, 4]}}
        cros_config_schema.MergeDictionaries(primary, overlay)
        self.assertEqual({"a": {"b": 1, "c": [1, 2, 3, 4]}}, primary)


class ParseArgsTests(cros_test_lib.TestCase):
    def testParseArgs(self):
        argv = ["-s", "schema", "-c", "config", "-o", "output", "-f", "True"]
        args = cros_config_schema.ParseArgs(argv)
        self.assertEqual(args.schema, "schema")
        self.assertEqual(args.config, "config")
        self.assertEqual(args.output, "output")
        self.assertTrue(args.filter)

    def testParseArgsForConfigs(self):
        argv = ["-o", "output", "-m", "m1", "m2", "m3"]
        args = cros_config_schema.ParseArgs(argv)
        self.assertEqual(args.output, "output")
        self.assertEqual(args.configs, ["m1", "m2", "m3"])


class TransformConfigTests(cros_test_lib.TestCase):
    def testBasicTransform(self):
        result = cros_config_schema.TransformConfig(BASIC_CONFIG)
        json_dict = json.loads(result)
        self.assertEqual(len(json_dict), 1)
        configs = json_dict["chromeos"]["configs"]
        self.assertEqual(1, len(configs))
        model = configs[0]
        self.assertEqual("basking", model["name"])
        self.assertEqual("basking", model["audio"]["main"]["cras-config-dir"])
        # Check multi-level template variable evaluation
        self.assertEqual(
            "/etc/cras/basking/dsp.ini",
            model["audio"]["main"]["files"][0]["destination"],
        )

    def testTransformConfig_NoMatch(self):
        result = cros_config_schema.TransformConfig(
            BASIC_CONFIG, model_filter_regex="abc123"
        )
        json_dict = json.loads(result)
        self.assertEqual(0, len(json_dict["chromeos"]["configs"]))

    def testTransformConfig_FilterMatch(self):
        scoped_config = """
reef-9042-fw: &reef-9042-fw
  bcs-overlay: 'overlay-reef-private'
  ec-ro-image: 'Reef_EC.9042.87.1.tbz2'
  main-ro-image: 'Reef.9042.87.1.tbz2'
  main-rw-image: 'Reef.9042.110.0.tbz2'
  build-targets:
    coreboot: 'reef'
chromeos:
  devices:
    - $name: 'foo'
      products:
        - $key-id: 'OEM2'
      skus:
        - config:
            identity:
              sku-id: 0
            audio:
              main:
                cras-config-dir: '{{$name}}'
                ucm-suffix: '{{$name}}'
            name: '{{$name}}'
            firmware: *reef-9042-fw
            firmware-signing:
              key-id: '{{$key-id}}'
              signature-id: '{{$name}}'
    - $name: 'bar'
      products:
        - $key-id: 'OEM2'
      skus:
        - config:
            identity:
              sku-id: 0
            audio:
              main:
                cras-config-dir: '{{$name}}'
                ucm-suffix: '{{$name}}'
            name: '{{$name}}'
            firmware: *reef-9042-fw
            firmware-signing:
              key-id: '{{$key-id}}'
              signature-id: '{{$name}}'
"""

        result = cros_config_schema.TransformConfig(
            scoped_config, model_filter_regex="bar"
        )
        json_dict = json.loads(result)
        configs = json_dict["chromeos"]["configs"]
        self.assertEqual(1, len(configs))
        model = configs[0]
        self.assertEqual("bar", model["name"])

    def testTemplateVariableScope(self):
        scoped_config = """
audio_common: &audio_common
  main:
    $ucm: "default"
    $cras: "default"
    ucm-suffix: "{{$ucm}}"
    cras-config-dir: "{{$cras}}"
chromeos:
  devices:
    - $name: "some"
      $ucm: "overridden-by-device-scope"
      products:
        - $key-id: 'SOME-KEY'
          $brand-code: 'SOME-BRAND'
          $cras: "overridden-by-product-scope"
      skus:
        - $sku-id: 0
          config:
            audio: *audio_common
            brand-code: '{{$brand-code}}'
            identity:
              platform-name: "Some"
              frid: "Google_Some"
            name: '{{$name}}'
            firmware:
              no-firmware: True
"""
        result = cros_config_schema.TransformConfig(scoped_config)
        json_dict = json.loads(result)
        config = json_dict["chromeos"]["configs"][0]
        audio_main = config["audio"]["main"]
        self.assertEqual(
            "overridden-by-product-scope", audio_main["cras-config-dir"]
        )
        self.assertEqual("overridden-by-device-scope", audio_main["ucm-suffix"])


class ValidateConfigSchemaTests(cros_test_lib.TestCase):
    def setUp(self):
        self._schema = cros_config_schema.ReadSchema()

    def testBasicSchemaValidation(self):
        libcros_schema.ValidateConfigSchema(
            self._schema, cros_config_schema.TransformConfig(BASIC_CONFIG)
        )

    def testMissingRequiredElement(self):
        config = re.sub(r" *cras-config-dir: .*", "", BASIC_CONFIG)
        config = re.sub(r" *volume: .*", "", BASIC_CONFIG)
        try:
            libcros_schema.ValidateConfigSchema(
                self._schema, cros_config_schema.TransformConfig(config)
            )
        except jsonschema.ValidationError as err:
            self.assertIn("required", err.__str__())
            self.assertIn("cras-config-dir", err.__str__())

    def testReferencedNonExistentTemplateVariable(self):
        config = re.sub(r" *$card: .*", "", BASIC_CONFIG)
        try:
            libcros_schema.ValidateConfigSchema(
                self._schema, cros_config_schema.TransformConfig(config)
            )
        except cros_config_schema.ValidationError as err:
            self.assertIn("Referenced template variable", err.__str__())
            self.assertIn("cras-config-dir", err.__str__())

    def testSkuIdOutOfBound(self):
        config = BASIC_CONFIG.replace("$sku-id: 0", "$sku-id: 0x80000000")
        with self.assertRaises(jsonschema.ValidationError) as ctx:
            libcros_schema.ValidateConfigSchema(
                self._schema, cros_config_schema.TransformConfig(config)
            )
        if version.parse(jsonschema.__version__) >= version.Version("3.0.0"):
            self.assertIn(
                "%i is greater than the maximum" % 0x80000000,
                str(ctx.exception),
            )
            self.assertIn("sku-id", str(ctx.exception))
        else:
            self.assertIn("'sku-id': %i" % 0x80000000, str(ctx.exception))
            self.assertIn("is not valid", str(ctx.exception))


class ValidateFingerprintSchema(cros_test_lib.TestCase):
    def setUp(self):
        self._schema = cros_config_schema.ReadSchema()

    def testROVersion(self):
        config = {
            "chromeos": {
                "configs": [
                    {
                        "identity": {"platform-name": "foo", "sku-id": 1},
                        "name": "foo",
                        "fingerprint": {
                            "board": "dartmonkey",
                            "ro-version": "123",
                        },
                    },
                ],
            },
        }
        libcros_schema.ValidateConfigSchema(
            self._schema, libcros_schema.FormatJson(config)
        )

    def testROVersionMissingBoardName(self):
        config = {
            "chromeos": {
                "configs": [
                    {
                        "identity": {"platform-name": "foo", "sku-id": 1},
                        "name": "foo",
                        "fingerprint": {
                            # "ro-version" only allowed if "board" is also
                            # specified.
                            "ro-version": "123"
                        },
                    },
                ],
            },
        }
        with self.assertRaises(jsonschema.exceptions.ValidationError) as ctx:
            libcros_schema.ValidateConfigSchema(
                self._schema, libcros_schema.FormatJson(config)
            )

        self.assertEqual(
            ctx.exception.message, "'board' is a dependency of 'ro-version'"
        )


class ValidateCameraSchema(cros_test_lib.TestCase):
    def setUp(self):
        self._schema = cros_config_schema.ReadSchema()

    def testDevices(self):
        config = {
            "chromeos": {
                "configs": [
                    {
                        "identity": {"platform-name": "foo", "sku-id": 1},
                        "name": "foo",
                        "camera": {
                            "count": 2,
                            "devices": [
                                {
                                    "interface": "usb",
                                    "facing": "front",
                                    "orientation": 180,
                                    "flags": {
                                        "support-1080p": False,
                                        "support-autofocus": False,
                                    },
                                    "ids": ["0123:abcd", "4567:efef"],
                                },
                                {
                                    "interface": "mipi",
                                    "facing": "back",
                                    "orientation": 0,
                                    "flags": {
                                        "support-1080p": True,
                                        "support-autofocus": True,
                                    },
                                },
                            ],
                        },
                    },
                ],
            },
        }
        libcros_schema.ValidateConfigSchema(
            self._schema, libcros_schema.FormatJson(config)
        )

    def testInvalidUsbId(self):
        if version.parse(jsonschema.__version__) < version.Version("3.0.0"):
            self.skipTest("jsonschema needs upgrade to support conditionals")

        for invalid_usb_id in ("0123-abcd", "0123:Abcd", "123:abcd"):
            config = {
                "chromeos": {
                    "configs": [
                        {
                            "identity": {"platform-name": "foo", "sku-id": 1},
                            "name": "foo",
                            "camera": {
                                "count": 1,
                                "devices": [
                                    {
                                        "interface": "usb",
                                        "facing": "front",
                                        "orientation": 0,
                                        "flags": {
                                            "support-1080p": False,
                                            "support-autofocus": True,
                                        },
                                        "ids": [invalid_usb_id],
                                    },
                                ],
                            },
                        },
                    ],
                },
            }
            with self.assertRaises(jsonschema.ValidationError) as ctx:
                libcros_schema.ValidateConfigSchema(
                    self._schema, libcros_schema.FormatJson(config)
                )
            self.assertIn(
                "%r does not match" % invalid_usb_id, str(ctx.exception)
            )


CUSTOM_LABEL_CONFIG = """
chromeos:
  devices:
    - $name: 'customlabel'
      products:
        - $key-id: 'DEFAULT'
          $wallpaper: 'DEFAULT_WALLPAPER'
          $regulatory-label: 'DEFAULT_LABEL'
          $custom-label-tag: ''
          $brand-code: 'DEFAULT_BRAND_CODE'
          $stylus-category: 'none'
          $test-label: 'DEFAULT_TEST_LABEL'
        - $key-id: 'CUSTOM1'
          $wallpaper: 'CUSTOM1_WALLPAPER'
          $regulatory-label: 'CUSTOM1_LABEL'
          $custom-label-tag: 'CUSTOM1_TAG'
          $brand-code: 'CUSTOM1_BRAND_CODE'
          $oem-name: 'CUSTOM1_OEM_NAME'
          $stylus-category: 'none'
          $test-label: 'CUSTOM1_TEST_LABEL'
          $marketing-name: 'BRAND1_MARKETING_NAME1'
          $extra-ash-feature: 'CloudGamingDevice'
        - $key-id: 'CUSTOM2'
          $wallpaper: 'CUSTOM2_WALLPAPER'
          $regulatory-label: 'CUSTOM2_LABEL'
          $custom-label-tag: 'CUSTOM2_TAG'
          $brand-code: 'CUSTOM2_BRAND_CODE'
          $oem-name: 'CUSTOM2_OEM_NAME'
          $stylus-category: 'external'
          $test-label: 'CUSTOM2_TEST_LABEL'
          $marketing-name: 'BRAND2_MARKETING_NAME2'
          $extra-ash-feature: '{{$test-extra-ash-feature}}'
      skus:
        - config:
            identity:
              sku-id: 0
              custom-label-tag: '{{$custom-label-tag}}'
            name: '{{$name}}'
            brand-code: '{{$brand-code}}'
            wallpaper: '{{$wallpaper}}'
            regulatory-label: '{{$regulatory-label}}'
            hardware-properties:
              stylus-category: '{{$stylus-category}}'
            arc:
              build-properties:
                $marketing-name: ''
                marketing-name: '{{$marketing-name}}'
            branding:
              $oem-name: ''
              oem-name: '{{$oem-name}}'
              marketing-name: '{{$marketing-name}}'
            ui:
              ash-enabled-features:
              - CommonFeature
              - '{{$extra-ash-feature}}'
              $extra-ash-feature: ''
              $test-extra-ash-feature: ''
"""

INVALID_CUSTOM_LABEL_CONFIG = """
            # THIS WILL CAUSE THE FAILURE
            test-label: '{{$test-label}}'
"""

INVALID_CUSTOM_LABEL_CONFIG_FEATURE = """
            # THIS WILL CAUSE THE FAILURE
            $test-extra-ash-feature: 'OtherFeature'
"""


class ValidateConfigTests(cros_test_lib.TestCase):
    def testBasicValidation(self):
        cros_config_schema.ValidateConfig(
            cros_config_schema.TransformConfig(BASIC_CONFIG)
        )

    def testIdentitiesNotUnique(self):
        config = """
reef-9042-fw: &reef-9042-fw
  bcs-overlay: 'overlay-reef-private'
  ec-ro-image: 'Reef_EC.9042.87.1.tbz2'
  main-ro-image: 'Reef.9042.87.1.tbz2'
  main-rw-image: 'Reef.9042.110.0.tbz2'
  build-targets:
    coreboot: 'reef'
chromeos:
  devices:
    - $name: 'astronaut'
      products:
        - $key-id: 'OEM2'
      skus:
        - config:
            identity:
              sku-id: 0
            audio:
              main:
                cras-config-dir: '{{$name}}'
                ucm-suffix: '{{$name}}'
            name: '{{$name}}'
            firmware: *reef-9042-fw
            firmware-signing:
              key-id: '{{$key-id}}'
              signature-id: '{{$name}}'
    - $name: 'astronaut'
      products:
        - $key-id: 'OEM2'
      skus:
        - config:
            identity:
              sku-id: 0
            audio:
              main:
                cras-config-dir: '{{$name}}'
                ucm-suffix: '{{$name}}'
            name: '{{$name}}'
            firmware: *reef-9042-fw
            firmware-signing:
              key-id: '{{$key-id}}'
              signature-id: '{{$name}}'
"""
        with self.assertRaises(cros_config_schema.ValidationError) as ctx:
            cros_config_schema.ValidateConfig(
                cros_config_schema.TransformConfig(config)
            )
        self.assertIn("Identities are not unique", str(ctx.exception))

    def testCustomLabelWithExternalStylusAndCloudGamingFeature(self):
        config = CUSTOM_LABEL_CONFIG
        cros_config_schema.ValidateConfig(
            cros_config_schema.TransformConfig(config)
        )

    def testCustomLabelWithOtherThanBrandChanges(self):
        config = CUSTOM_LABEL_CONFIG + INVALID_CUSTOM_LABEL_CONFIG
        with self.assertRaises(cros_config_schema.ValidationError) as ctx:
            cros_config_schema.ValidateConfig(
                cros_config_schema.TransformConfig(config)
            )
        self.assertIn("Custom label configs can only", str(ctx.exception))

    def testCustomLabelWithFeatureFlagOtherThanBrandChanges(self):
        config = CUSTOM_LABEL_CONFIG + INVALID_CUSTOM_LABEL_CONFIG_FEATURE
        with self.assertRaises(cros_config_schema.ValidationError) as ctx:
            cros_config_schema.ValidateConfig(
                cros_config_schema.TransformConfig(config)
            )
        self.assertIn("Custom label configs can only", str(ctx.exception))

    def testHardwarePropertiesInvalid(self):
        config = """
chromeos:
  devices:
    - $name: 'bad_device'
      skus:
        - config:
            identity:
              sku-id: 0
            # THIS WILL CAUSE THE FAILURE
            hardware-properties:
              has-base-accelerometer: true
              has-base-gyroscope: 7
              has-lid-accelerometer: false
              is-lid-convertible: false
              has-base-magnetometer: false
              has-touchscreen: true
"""
        try:
            cros_config_schema.ValidateConfig(
                cros_config_schema.TransformConfig(config)
            )
        except cros_config_schema.ValidationError as err:
            self.assertIn("must be boolean", err.__str__())
        else:
            self.fail("ValidationError not raised")

    def testHardwarePropertiesBoolean(self):
        config = """
chromeos:
  devices:
    - $name: 'good_device'
      skus:
        - config:
            identity:
              sku-id: 0
            hardware-properties:
              has-base-accelerometer: true
              has-base-gyroscope: true
              has-lid-accelerometer: true
              is-lid-convertible: false
              has-base-magnetometer: true
              has-touchscreen: false
"""
        cros_config_schema.ValidateConfig(
            cros_config_schema.TransformConfig(config)
        )

    def testMultipleFingerprintFirmwareROVersionInvalid(self):
        config = {
            "chromeos": {
                "configs": [
                    {
                        "identity": {"platform-name": "foo", "sku-id": 1},
                        "fingerprint": {
                            "board": "bloonchipper",
                            "ro-version": "123",
                        },
                    },
                    {
                        "identity": {"platform-name": "foo", "sku-id": 2},
                        "fingerprint": {
                            "board": "bloonchipper",
                            "ro-version": "123",
                        },
                    },
                    # This causes the ValidationError.
                    {
                        "identity": {"platform-name": "foo", "sku-id": 3},
                        "fingerprint": {
                            "board": "bloonchipper",
                            "ro-version": "456",
                        },
                    },
                ],
            },
        }
        with self.assertRaises(cros_config_schema.ValidationError) as ctx:
            cros_config_schema.ValidateConfig(json.dumps(config))

        self.assertRegex(
            str(ctx.exception),
            re.compile(
                "You may not use different fingerprint firmware RO versions "
                "on the same board:.*"
            ),
        )

    def testMultipleFingerprintFirmwareROVersionsValid(self):
        config = {
            "chromeos": {
                "configs": [
                    {
                        "identity": {"platform-name": "foo", "sku-id": 1},
                        "fingerprint": {
                            "board": "bloonchipper",
                            "ro-version": "123",
                        },
                    },
                    {
                        "identity": {"platform-name": "foo", "sku-id": 2},
                        "fingerprint": {
                            "board": "dartmonkey",
                            "ro-version": "456",
                        },
                    },
                ],
            },
        }
        cros_config_schema.ValidateConfig(json.dumps(config))

    def testFingerprintFirmwareROVersionsValid(self):
        config = {
            "chromeos": {
                "configs": [
                    {
                        "identity": {"platform-name": "foo", "sku-id": 1},
                        "fingerprint": {"ro-version": "123"},
                    },
                    # This device does not have fingerprint
                    {
                        "identity": {"platform-name": "foo", "sku-id": 2},
                    },
                ],
            },
        }
        cros_config_schema.ValidateConfig(json.dumps(config))


class FilterBuildElements(cros_test_lib.TestCase):
    def testBasicFilterBuildElements(self):
        json_dict = json.loads(
            cros_config_schema.FilterBuildElements(
                cros_config_schema.TransformConfig(BASIC_CONFIG), ["/firmware"]
            )
        )
        self.assertNotIn("firmware", json_dict["chromeos"]["configs"][0])


class GetValidSchemaProperties(cros_test_lib.TestCase):
    def testGetValidSchemaProperties(self):
        schema_props = cros_config_schema.GetValidSchemaProperties()
        self.assertIn("cras-config-dir", schema_props["/audio/main"])
        self.assertIn("key-id", schema_props["/firmware-signing"])
        self.assertIn("files", schema_props["/audio/main"])
        self.assertIn("has-touchscreen", schema_props["/hardware-properties"])
        self.assertIn("count", schema_props["/camera"])


def _GetSchemaYaml():
    schema_contents = cros_config_schema.ReadSchema()
    return libcros_schema.LoadYaml(schema_contents)


class SchemaContentsTests(cros_test_lib.TestCase):
    def testSchemaPropertyNames(self):
        """Validate that all property names use hyphen-case"""

        def _GetPropertyNames(obj, key_name):
            if key_name == "properties":
                yield from obj.keys()

            if isinstance(obj, dict):
                for key, value in obj.items():
                    yield from _GetPropertyNames(value, key)
            elif isinstance(obj, list):
                for item in obj:
                    yield from _GetPropertyNames(item, None)

        schema = _GetSchemaYaml()
        property_name_pattern = re.compile(r"^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
        for property_name in _GetPropertyNames(schema, None):
            self.assertRegex(
                property_name,
                property_name_pattern,
                "All property names must use hyphen-case.",
            )


class MainTests(cros_test_lib.TempDirTestCase):
    def assertFileEqual(self, file_expected, file_actual):
        self.assertTrue(
            os.path.isfile(file_expected),
            f"Expected file does not exist at path: {file_expected}",
        )

        self.assertTrue(
            os.path.isfile(file_actual),
            f"Actual file does not exist at path: {file_actual}",
        )

        regen_message = (
            "Please run ./regen.sh in the chromeos-config directory."
        )

        with open(file_expected, "r", encoding="utf-8") as expected, open(
            file_actual, "r", encoding="utf-8"
        ) as actual:
            for line_num, (line_expected, line_actual) in enumerate(
                zip_longest(expected, actual)
            ):
                self.assertEqual(
                    line_expected,
                    line_actual,
                    (
                        f"Files differ at line {line_num}\n"
                        f"Expected: {line_expected}\n"
                        f"Actual  : {line_actual}\n"
                        f"Path of expected output file: {file_expected}\n"
                        f"Path of actual output file: {file_actual}\n"
                        f"{regen_message}"
                    ),
                )

    def assertMultilineStringEqual(self, str_expected, str_actual):
        expected = str_expected.strip().split("\n")
        actual = str_actual.strip().split("\n")
        for line_num, (line_expected, line_actual) in enumerate(
            zip_longest(expected, actual)
        ):
            self.assertEqual(
                line_expected,
                line_actual,
                (
                    f"Strings differ at line {line_num}\n"
                    f"Expected: {line_expected!r}\n"
                    f"Actual  : {line_actual!r}\n"
                ),
            )

    def testMainWithExampleWithBuild(self):
        json_output = os.path.join(self.tempdir, "output.json")
        cros_config_schema.Main(
            None,
            os.path.join(this_dir, "../test_data/test.yaml"),
            json_output,
        )

        expected_json_file = os.path.join(
            this_dir, "../test_data/test_build.json"
        )
        self.assertFileEqual(expected_json_file, json_output)

    def testMainWithExampleWithoutBuild(self):
        output = os.path.join(self.tempdir, "output")
        cros_config_schema.Main(
            None,
            os.path.join(this_dir, "../test_data/test.yaml"),
            output,
            filter_build_details=True,
        )

        expected_file = os.path.join(this_dir, "../test_data/test.json")
        self.assertFileEqual(expected_file, output)

    def testMainArmExample(self):
        json_output = os.path.join(self.tempdir, "output.json")
        cros_config_schema.Main(
            None,
            os.path.join(this_dir, "../test_data/test_arm.yaml"),
            json_output,
            filter_build_details=True,
        )

        expected_json_file = os.path.join(
            this_dir, "../test_data/test_arm.json"
        )
        self.assertFileEqual(expected_json_file, json_output)

    def testMainImportExample(self):
        output = os.path.join(self.tempdir, "output")
        cros_config_schema.Main(
            None,
            os.path.join(this_dir, "../test_data/test_import.yaml"),
            output,
        )
        expected_file = os.path.join(this_dir, "../test_data/test_import.json")
        self.assertFileEqual(expected_file, output)

    def testMainMergeExample(self):
        output = os.path.join(self.tempdir, "output")
        base_path = os.path.join(this_dir, "../test_data")
        cros_config_schema.Main(
            None,
            None,
            output,
            configs=[
                os.path.join(base_path, "test_merge_base.yaml"),
                os.path.join(base_path, "test_merge_overlay.yaml"),
            ],
        )
        expected_file = os.path.join(this_dir, "../test_data/test_merge.json")
        self.assertFileEqual(expected_file, output)

    def testMainZephyrFilter(self):
        output = os.path.join(self.tempdir, "output")
        base_path = os.path.join(this_dir, "../test_data")
        cros_config_schema.Main(
            None,
            None,
            output,
            configs=[os.path.join(base_path, "test.yaml")],
            zephyr_ec_configs_only=True,
        )
        expected_file = os.path.join(base_path, "test_zephyr.json")
        self.assertFileEqual(expected_file, output)

    def testIdentityTableOut(self):
        base_path = os.path.join(this_dir, "../test_data")
        output = io.BytesIO()
        for fname in ("test.yaml", "test_arm.yaml"):
            with contextlib.redirect_stdout(io.StringIO()):
                cros_config_schema.Main(
                    None,
                    None,
                    None,
                    configs=[os.path.join(base_path, fname)],
                    identity_table_out=output,
                )
            # crosid unittests go in depth with testing the file
            # contents/format.  We just check that we put some good looking
            # data there (greater than 32 bytes is required).
        self.assertGreater(len(output.getvalue()), 32)


if __name__ == "__main__":
    cros_test_lib.main(module=__name__)
