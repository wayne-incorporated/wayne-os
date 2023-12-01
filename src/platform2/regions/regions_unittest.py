#!/usr/bin/env python3
#
# Copyright 2015 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Tests for regions.py.

These tests ensure that all regions in regions.py are valid.  The tests use
testdata pulled from the Chromium sources.
"""

from __future__ import print_function

import io
import logging
import os
import unittest

import yaml  # pylint: disable=import-error

import regions


_WARN_UNKNOWN_DATA_IN_UNCONFIRMED_REGION = (
    "Missing %s %r; does this new data need to be added to CrOS, or "
    "does testdata need to be updated? (just a warning, since region "
    "%r is not a confirmed region)"
)

CustomLoader = yaml.SafeLoader
CustomLoader.add_constructor(
    "tag:yaml.org,2002:python/tuple", CustomLoader.construct_yaml_seq
)


class RegionTest(unittest.TestCase):
    """Tests for the Region class."""

    @classmethod
    def _ReadTestData(cls, name):
        """Reads a YAML-formatted test data file.

        Args:
          name: Name of file in the testdata directory.

        Returns:
          The parsed value.
        """
        with open(
            os.path.join(os.path.dirname(__file__), "testdata", name + ".yaml")
        ) as f:
            return yaml.load(f, Loader=CustomLoader)

    @classmethod
    def setUpClass(cls):
        cls.locales = cls._ReadTestData("locales")
        cls.time_zones = cls._ReadTestData("time_zones")
        cls.migration_map = cls._ReadTestData("migration_map")
        cls.input_methods = cls._ReadTestData("input_methods")

    def _ResolveInputMethod(self, method):
        """Resolves an input method using the migration map.

        Args:
          method: An input method ID that may contain prefixes from the
              migration map.  (E.g., "m17n:ar", which contains the "m17n:" prefix.)

        Returns:
          The input method ID after mapping any prefixes.  (E.g., "m17n:ar" will
          be mapped to "vkd_".)
        """
        for k, v in self.migration_map:
            if method.startswith(k):
                method = v + method[len(k) :]
        return method

    def testZoneInfo(self):
        all_regions = regions.BuildRegionsDict(include_all=True)

        # Make sure all time zones are present in /usr/share/zoneinfo.
        all_zoneinfos = [
            os.path.join("/usr/share/zoneinfo", tz)
            for r in all_regions.values()
            for tz in r.time_zones
        ]
        missing = [z for z in all_zoneinfos if not os.path.exists(z)]
        self.assertFalse(
            missing,
            ("Missing zoneinfo files; are timezones misspelled?: %r" % missing),
        )

    def testBadLocales(self):
        self.assertRaisesRegex(
            AssertionError,
            "Locale 'en-us' does not match",
            regions.Region,
            "us",
            "xkb:us::eng",
            "America/Los_Angeles",
            "en-us",
            "ANSI",
        )

    def testBadKeyboard(self):
        self.assertRaisesRegex(
            AssertionError,
            "Keyboard pattern 'xkb:us::' does not match",
            regions.Region,
            "us",
            "xkb:us::",
            "America/Los_Angeles",
            "en-US",
            "ANSI",
        )

    def testKeyboardRegexp(self):
        self.assertTrue(regions.KEYBOARD_PATTERN.match("xkb:us::eng"))
        self.assertTrue(regions.KEYBOARD_PATTERN.match("ime:ko:korean"))
        self.assertTrue(regions.KEYBOARD_PATTERN.match("m17n:ar"))
        self.assertFalse(regions.KEYBOARD_PATTERN.match("m17n:"))
        self.assertFalse(regions.KEYBOARD_PATTERN.match("foo_bar"))

    def testTimeZones(self):
        for r in regions.BuildRegionsDict(include_all=True).values():
            for tz in r.time_zones:
                if tz not in self.time_zones:
                    if r.region_code in regions.REGIONS:
                        self.fail(
                            "Missing time zones: %r; does a new time zone need to be added "
                            "to CrOS, or does testdata need to be updated?" % tz
                        )
                    else:
                        # This is an unconfirmed region; just print a warning.
                        logging.warning(
                            _WARN_UNKNOWN_DATA_IN_UNCONFIRMED_REGION,
                            "time zone",
                            tz,
                            r.region_code,
                        )

    def testLocales(self):
        missing = []
        for r in regions.BuildRegionsDict(include_all=True).values():
            for l in r.locales:
                if l not in self.locales:
                    if r.region_code in regions.REGIONS:
                        missing.append(l)
                    else:
                        logging.warning(
                            _WARN_UNKNOWN_DATA_IN_UNCONFIRMED_REGION,
                            "locale",
                            l,
                            r.region_code,
                        )
        self.assertFalse(
            missing,
            ("Missing locale; does testdata need to be updated?: %r" % missing),
        )

    def testInputMethods(self):
        # Verify that every region is present in the dict.
        for r in regions.BuildRegionsDict(include_all=True).values():
            for k in r.keyboards:
                resolved_method = self._ResolveInputMethod(k)
                # Make sure the keyboard method is present.
                if resolved_method not in self.input_methods:
                    if r.region_code in regions.REGIONS:
                        self.fail(
                            "Missing keyboard layout %r (resolved from %r)"
                            % (resolved_method, k)
                        )
                    else:
                        # This is an unconfirmed region; just print a warning.
                        logging.warning(
                            _WARN_UNKNOWN_DATA_IN_UNCONFIRMED_REGION,
                            "keyboard",
                            k,
                            r.region_code,
                        )

    def testFirmwareLocales(self):
        # This file is probably in src/platform2/regions
        src_root = os.environ.get(
            "CROS_WORKON_SRCROOT",
            os.path.join(os.path.dirname(__file__), "..", "..", ".."),
        )
        bmpblk_dir = os.path.join(src_root, "src", "platform", "bmpblk")
        if not os.path.exists(bmpblk_dir):
            logging.warning(
                "Skipping testFirmwareLocales, since %r is missing", bmpblk_dir
            )
            return

        bmp_locale_dir = os.path.join(bmpblk_dir, "strings", "locale")
        for r in regions.BuildRegionsDict(include_all=True).values():
            checked_paths = []
            for l in r.locales:
                paths = [os.path.join(bmp_locale_dir, l)]
                if "-" in l:
                    paths.append(
                        os.path.join(bmp_locale_dir, l.partition("-")[0])
                    )
                if any(os.path.exists(x) for x in paths):
                    break
                checked_paths += paths
            else:
                if r.region_code in regions.REGIONS:
                    self.fail(
                        "For region %r, none of %r exists"
                        % (r.region_code, checked_paths)
                    )
                else:
                    logging.warning(
                        "For region %r, none of %r exists; "
                        "just a warning since this region is not confirmed",
                        r.region_code,
                        checked_paths,
                    )

    def testYAMLOutput(self):
        output = io.StringIO()
        regions.main(["--format", "yaml"], output)
        data = yaml.load(output.getvalue(), Loader=CustomLoader)
        self.assertEqual(
            {
                "keyboards": ["xkb:us::eng"],
                "keyboard_mechanical_layout": "ANSI",
                "locales": ["en-US"],
                "region_code": "us",
                "description": "United States",
                "regulatory_domain": "US",
                "time_zones": ["America/Los_Angeles"],
            },
            data["us"],
        )

    def testFieldsDict(self):
        # 'description' and 'notes' should be missing.
        self.assertEqual(
            {
                "keyboards": ["xkb:b::b"],
                "keyboard_mechanical_layout": "e",
                "description": "description",
                "locales": ["d"],
                "region_code": "aa",
                "regulatory_domain": "AA",
                "time_zones": ["c"],
            },
            (
                regions.Region(
                    "aa", "xkb:b::b", "c", "d", "e", "description", "notes"
                ).GetFieldsDict()
            ),
        )

    def testConsolidateRegionsDups(self):
        """Test duplicate handling.  Two identical Regions are OK."""
        # Make two copies of the same region.
        region_list = [
            regions.Region("aa", "xkb:b::b", "c", "d", "e") for _ in range(2)
        ]
        # It's OK.
        self.assertEqual(
            {"aa": region_list[0]}, regions.ConsolidateRegions(region_list)
        )

        # Modify the second copy.
        region_list[1].keyboards = ["f"]
        # Not OK anymore!
        self.assertRaisesRegex(
            regions.RegionException,
            "Conflicting definitions for region 'aa':",
            regions.ConsolidateRegions,
            region_list,
        )


if __name__ == "__main__":
    logging.basicConfig(format="%(message)s", level=logging.WARNING)
    unittest.main()
