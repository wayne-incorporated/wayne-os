#!/usr/bin/env python3

# Copyright 2015 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.


"""Updates testdata/ based on data pulled from Chromium sources."""

from __future__ import print_function

import argparse
import base64
import json
import logging
import os
import re
import subprocess
import sys

import yaml  # pylint: disable=import-error


# URLs to GIT paths.
SRC_GIT_URL = "https://chromium.googlesource.com/chromium/src/+/HEAD/"

TESTDATA_PATH = os.path.join(os.path.dirname(__file__), "testdata")


def GetChromiumSource(file_path):
    """Gets Chromium source code by given path.

    Args:
      file_path: The relative path to retrieve.
    """
    return base64.b64decode(
        subprocess.check_output(
            ["curl", "-s", SRC_GIT_URL + file_path + "?format=TEXT"]
        )
    ).decode("utf-8")


def WriteTestData(name, value):
    if not value:
        sys.exit("No values found for %s" % name)

    path = os.path.join(TESTDATA_PATH, name + ".yaml")
    logging.info("%s: writing %r", path, value)
    with open(path, "w") as f:
        f.write(
            "# Automatically generated from ToT Chromium sources\n"
            "# by update_testdata.py. Do not edit manually.\n"
            "\n"
        )
        yaml.dump(value, f, default_flow_style=False)


def UpdateLocales():
    """Updates locales.

    Valid locales are entries of the kAcceptLanguageList array in
    l10n_util.cc <http://goo.gl/z8XsZJ>.
    """
    cpp_code = GetChromiumSource("ui/base/l10n/l10n_util.cc")
    match = re.search(
        r"static[^\n]+kAcceptLanguageList\[\] = \{(.+?)^\}",
        cpp_code,
        re.DOTALL | re.MULTILINE,
    )
    if not match:
        sys.exit("Unable to find language list")

    locales = re.findall(r'"(.+)"', match.group(1))
    if not locales:
        sys.exit("Unable to parse language list")

    WriteTestData("locales", sorted(locales))


def UpdateTimeZones():
    """Updates time zones.

    Valid time zones are values of the kTimeZones array in timezone_settings.cc
    <http://goo.gl/WSVUeE>.
    """
    cpp_code = GetChromiumSource(
        "chromeos/ash/components/settings/timezone_settings.cc"
    )
    match = re.search(
        r"static[^\n]+kTimeZones\[\] = \{(.+?)^\}",
        cpp_code,
        re.DOTALL | re.MULTILINE,
    )
    if not match:
        sys.exit("Unable to find time zones")

    time_zones = re.findall(r'"(.+)"', match.group(1))
    if not time_zones:
        sys.exit("Unable to parse time zones")

    WriteTestData("time_zones", time_zones)


def UpdateMigrationMap():
    """Updates the input method migration map.

    The source is the kEngineIdMigrationMap array in input_method_util.cc
    <https://chromium.googlesource.com/chromium/src/+/HEAD/ui/base/ime/ash/input_method_util.cc>.
    """
    cpp_code = GetChromiumSource("ui/base/ime/ash/input_method_util.cc")
    match = re.search(
        r"kEngineIdMigrationMap\[\]\[2\] = \{(.+?)^\}",
        cpp_code,
        re.DOTALL | re.MULTILINE,
    )
    if not match:
        sys.exit("Unable to find kEngineIdMigrationMap")

    map_code = match.group(1)
    migration_map = re.findall(r'{"(.+?)", "(.+?)"}', map_code)
    if not migration_map:
        sys.exit("Unable to parse kEngineIdMigrationMap")

    WriteTestData("migration_map", migration_map)


def UpdateInputMethods():
    """Updates input method IDs.

    This is the union of all 'id' fields in input_method/*.json
    <http://goo.gl/z4JGvK>.
    """
    # entry format: 100644 blob 48de6e64885e472c6743543cc988ac0fd8edd55e    FILE
    json_dir = "chrome/browser/resources/chromeos/input_method"
    files = [
        line.strip().split()[-1]
        for line in GetChromiumSource(json_dir).splitlines()
    ]
    pattern = re.compile(r"\.json$")
    json_files = [f for f in files if pattern.search(f)]

    input_methods = set()
    for f in json_files:
        contents = json.loads(GetChromiumSource(os.path.join(json_dir, f)))
        for c in contents["input_components"]:
            input_methods.add(str(c["id"]))

    WriteTestData("input_methods", sorted(input_methods))


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Updates some constants in regions_unittest_data.py based "
            "on data pulled from Chromium sources. This overwrites "
            "files in testdata, which you must then submit."
        )
    )
    unused_args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)

    UpdateLocales()
    UpdateTimeZones()
    UpdateInputMethods()
    UpdateMigrationMap()

    logging.info('Run "git diff %s" to see changes (if any).', TESTDATA_PATH)
    logging.info("Make sure to submit any changes to %s!", TESTDATA_PATH)


if __name__ == "__main__":
    main()
