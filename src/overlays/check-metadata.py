#!/usr/bin/env python3
# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Require every overlay have good metadata in the root directory.

If no files are specified, all overlays will be checked.
"""

import dataclasses
import logging
from pathlib import Path
import site
import sys
from typing import List, Optional


DIR = Path(__file__).resolve().parent

# pylint: disable=wrong-import-position
site.addsitedir(DIR.parent.parent)

from chromite.lib import commandline


assert sys.version_info >= (3, 8), "This module requires Python 3.8+"


# The files we check.
METADATA = ("DIR_METADATA", "OWNERS", "README.md")


# Overlays that haven't added metadata yet.  Do not add any more entries.
MISSING_OVERLAYS_DIR_METADATA = {
    "baseboard-asurada",
    "baseboard-brya",
    "baseboard-cherry",
    "baseboard-coral",
    "baseboard-corsola",
    "baseboard-dedede",
    "baseboard-drallion",
    "baseboard-fizz",
    "baseboard-glados",
    "baseboard-gru",
    "baseboard-grunt",
    "baseboard-hatch",
    "baseboard-herobrine",
    "baseboard-jecht",
    "baseboard-kalista",
    "baseboard-keeby",
    "baseboard-krabbylake",
    "baseboard-kukui",
    "baseboard-kunimitsu",
    "baseboard-nami",
    "baseboard-oak",
    "baseboard-octopus",
    "baseboard-poppy",
    "baseboard-puff",
    "baseboard-rammus",
    "baseboard-reef",
    "baseboard-rex",
    "baseboard-sarien",
    "baseboard-trogdor",
    "baseboard-volteer",
    "chipset-adl",
    "chipset-adln",
    "chipset-apl",
    "chipset-bdw",
    "chipset-cezanne",
    "chipset-cml",
    "chipset-glk",
    "chipset-jsl",
    "chipset-kbl",
    "chipset-mendocino",
    "chipset-mt8173",
    "chipset-mt8183",
    "chipset-mt8186",
    "chipset-mt8192",
    "chipset-mt8195",
    "chipset-mtl",
    "chipset-picasso",
    "chipset-qc7180",
    "chipset-rk3399",
    "chipset-rpl",
    "chipset-sc7280",
    "chipset-skl",
    "chipset-stnyridge",
    "chipset-tgl",
    "chipset-whl",
    "overlay-amd64-generic",
    "overlay-amd64-generic-embedded",
    "overlay-amd64-host",
    "overlay-amd64-starnix",
    "overlay-arm64-generic",
    "overlay-arm-generic",
    "overlay-asuka",
    "overlay-asurada",
    "overlay-asurada64",
    "overlay-atlas",
    "overlay-aurora",
    "overlay-bob",
    "overlay-brask",
    "overlay-brya",
    "overlay-bubs",
    "overlay-caroline",
    "overlay-cave",
    "overlay-chell",
    "overlay-cherry",
    "overlay-cherry64",
    "overlay-coral",
    "overlay-corsola",
    "overlay-dedede",
    "overlay-draco",
    "overlay-elm",
    "overlay-eve",
    "overlay-fizz",
    "overlay-fizz-labstation",
    "overlay-fizz-satlab",
    "overlay-grunt",
    "overlay-guado",
    "overlay-guybrush",
    "overlay-hades",
    "overlay-hana",
    "overlay-hatch",
    "overlay-herobrine",
    "overlay-herobrine-kernelnext",
    "overlay-jacuzzi",
    "overlay-jacuzzi64",
    "overlay-kalista",
    "overlay-keeby",
    "overlay-kevin",
    "overlay-kevin64",
    "overlay-kukui",
    "overlay-lars",
    "overlay-majolica",
    "overlay-mushu",
    "overlay-nami",
    "overlay-nautilus",
    "overlay-nissa",
    "overlay-nocturne",
    "overlay-octopus",
    "overlay-passionfruit",
    "overlay-puff",
    "overlay-pyro",
    "overlay-rainier",
    "overlay-rammus",
    "overlay-reef",
    "overlay-rex",
    "overlay-sand",
    "overlay-scarlet",
    "overlay-senor",
    "overlay-sentry",
    "overlay-shotzo",
    "overlay-simple-fake-board",
    "overlay-skyrim",
    "overlay-snappy",
    "overlay-soraka",
    "overlay-soraka-libcamera",
    "overlay-strongbad",
    "overlay-strongbad-kernelnext",
    "overlay-tael",
    "overlay-tatl",
    "overlay-trogdor",
    "overlay-trogdor-kernelnext",
    "overlay-variant-guado-labstation",
    "overlay-volteer",
    "overlay-x32-generic",
    "overlay-x86-generic",
    "overlay-x86-generic-embedded",
    "overlay-zork",
    "project-labstation",
    "project-satlab",
    "project-termina",
}

MISSING_OVERLAYS_README_MD = {
    "baseboard-asurada",
    "baseboard-brya",
    "baseboard-coral",
    "baseboard-dedede",
    "baseboard-drallion",
    "baseboard-fizz",
    "baseboard-glados",
    "baseboard-gru",
    "baseboard-grunt",
    "baseboard-hatch",
    "baseboard-herobrine",
    "baseboard-jecht",
    "baseboard-kalista",
    "baseboard-keeby",
    "baseboard-krabbylake",
    "baseboard-kukui",
    "baseboard-kunimitsu",
    "baseboard-nami",
    "baseboard-oak",
    "baseboard-octopus",
    "baseboard-poppy",
    "baseboard-puff",
    "baseboard-rammus",
    "baseboard-reef",
    "baseboard-rex",
    "baseboard-sarien",
    "baseboard-trogdor",
    "baseboard-volteer",
    "chipset-adl",
    "chipset-adln",
    "chipset-apl",
    "chipset-bdw",
    "chipset-cezanne",
    "chipset-cml",
    "chipset-glk",
    "chipset-jsl",
    "chipset-kbl",
    "chipset-mendocino",
    "chipset-mt8173",
    "chipset-mt8183",
    "chipset-mt8192",
    "chipset-mtl",
    "chipset-phoenix",
    "chipset-picasso",
    "chipset-qc7180",
    "chipset-rk3399",
    "chipset-rpl",
    "chipset-sc7280",
    "chipset-skl",
    "chipset-stnyridge",
    "chipset-tgl",
    "chipset-whl",
    "overlay-amd64-generic",
    "overlay-amd64-generic-embedded",
    "overlay-amd64-host",
    "overlay-arm64-generic",
    "overlay-arm-generic",
    "overlay-asuka",
    "overlay-asurada",
    "overlay-asurada64",
    "overlay-atlas",
    "overlay-aurora",
    "overlay-bob",
    "overlay-brask",
    "overlay-brask-labstation",
    "overlay-brya",
    "overlay-bubs",
    "overlay-caroline",
    "overlay-cave",
    "overlay-chell",
    "overlay-cherry64",
    "overlay-coral",
    "overlay-dedede",
    "overlay-draco",
    "overlay-drallion",
    "overlay-elm",
    "overlay-eve",
    "overlay-fizz",
    "overlay-fizz-labstation",
    "overlay-fizz-moblab",
    "overlay-fizz-satlab",
    "overlay-galaxy",
    "overlay-grunt",
    "overlay-guado",
    "overlay-guybrush",
    "overlay-hades",
    "overlay-hana",
    "overlay-hatch",
    "overlay-herobrine",
    "overlay-herobrine-kernelnext",
    "overlay-jacuzzi",
    "overlay-jacuzzi64",
    "overlay-kalista",
    "overlay-keeby",
    "overlay-kevin",
    "overlay-kevin64",
    "overlay-kukui",
    "overlay-lars",
    "overlay-majolica",
    "overlay-mushu",
    "overlay-myst",
    "overlay-nami",
    "overlay-nautilus",
    "overlay-nissa",
    "overlay-nocturne",
    "overlay-octopus",
    "overlay-puff",
    "overlay-pyro",
    "overlay-rainier",
    "overlay-rammus",
    "overlay-reef",
    "overlay-rex",
    "overlay-sand",
    "overlay-sarien",
    "overlay-scarlet",
    "overlay-senor",
    "overlay-sentry",
    "overlay-shotzo",
    "overlay-skyrim",
    "overlay-snappy",
    "overlay-soraka",
    "overlay-soraka-libcamera",
    "overlay-strongbad",
    "overlay-strongbad-kernelnext",
    "overlay-trogdor",
    "overlay-trogdor-kernelnext",
    "overlay-variant-guado-labstation",
    "overlay-volteer",
    "overlay-x32-generic",
    "overlay-x86-generic",
    "overlay-x86-generic-embedded",
    "overlay-zork",
    "project-labstation",
    "project-mobbase",
    "project-moblab",
    "project-satlab",
    "project-wilco",
}

MISSING_OVERLAYS_OWNERS = {
    "baseboard-coral",
    "baseboard-fizz",
    "baseboard-glados",
    "baseboard-gru",
    "baseboard-grunt",
    "baseboard-hatch",
    "baseboard-jecht",
    "baseboard-kalista",
    "baseboard-krabbylake",
    "baseboard-kunimitsu",
    "baseboard-nami",
    "baseboard-poppy",
    "baseboard-rammus",
    "baseboard-reef",
    "baseboard-sarien",
    "baseboard-volteer",
    "chipset-apl",
    "chipset-bdw",
    "chipset-cml",
    "chipset-glk",
    "chipset-kbl",
    "chipset-picasso",
    "chipset-rk3399",
    "chipset-rpl",
    "chipset-skl",
    "chipset-stnyridge",
    "chipset-tgl",
    "chipset-whl",
    "overlay-amd64-generic",
    "overlay-amd64-generic-embedded",
    "overlay-arm64-generic",
    "overlay-arm-generic",
    "overlay-asuka",
    "overlay-atlas",
    "overlay-bob",
    "overlay-brask",
    "overlay-caroline",
    "overlay-cave",
    "overlay-chell",
    "overlay-cherry64",
    "overlay-coral",
    "overlay-draco",
    "overlay-eve",
    "overlay-fizz",
    "overlay-fizz-satlab",
    "overlay-galaxy",
    "overlay-grunt",
    "overlay-guado",
    "overlay-hatch",
    "overlay-kalista",
    "overlay-kevin",
    "overlay-lars",
    "overlay-majolica",
    "overlay-mushu",
    "overlay-nami",
    "overlay-nautilus",
    "overlay-nocturne",
    "overlay-pyro",
    "overlay-rainier",
    "overlay-rammus",
    "overlay-reef",
    "overlay-sand",
    "overlay-sarien",
    "overlay-scarlet",
    "overlay-sentry",
    "overlay-snappy",
    "overlay-soraka",
    "overlay-soraka-libcamera",
    "overlay-variant-guado-labstation",
    "overlay-volteer",
    "overlay-x32-generic",
    "overlay-x86-generic",
    "overlay-x86-generic-embedded",
    "project-satlab",
    "project-wilco",
}

MISSING_OVERLAYS = {
    "DIR_METADATA": MISSING_OVERLAYS_DIR_METADATA,
    "OWNERS": MISSING_OVERLAYS_OWNERS,
    "README.md": MISSING_OVERLAYS_README_MD,
}


@dataclasses.dataclass
class CheckResults:
    """Results from a checker."""

    # Whether the check passed.
    passed: bool

    # In case of failures, what went wrong.
    message: Optional[str] = None


DIR_METADATA_DOCS = """
Please see: https://chromium.googlesource.com/chromiumos/docs/+/HEAD/dir_metadata.md
"""


def check_content_dir_metadata(data: str) -> CheckResults:
    """Make sure DIR_METADATA content is reasonable."""
    # This is very rough, but the dirmd tool requires files on disk.
    # https://crbug.com/1343601
    has_b = "buganizer {" in data
    has_b_pub = "buganizer_public {" in data
    has_mono = "monorail {" in data
    if has_b and "component_id:" not in data:
        return CheckResults(
            False, "missing buganizer component_id" + DIR_METADATA_DOCS
        )
    if has_b_pub and "component_id:" not in data:
        return CheckResults(
            False, "missing public buganizer component_id" + DIR_METADATA_DOCS
        )
    if has_mono and not ("component:" in data or "project:" in data):
        return CheckResults(
            False,
            "missing monorail component and/or project" + DIR_METADATA_DOCS,
        )

    return CheckResults(
        any((has_b, has_b_pub, has_mono)),
        "missing bug tracker information" + DIR_METADATA_DOCS,
    )


def check_content_owners(data: str) -> CheckResults:
    """Make sure owners content is reasonable."""
    contents = []
    for line in data.splitlines():
        # Strip off comments.
        line = line.split("#", 1)[0].split()
        if not line:
            continue
        contents.append(line)
    if not contents:
        return CheckResults(False, "empty file")
    return CheckResults(True)


def check_content_readme_md(data: str):
    """Make sure README.md content is reasonable."""
    if not data.strip():
        return CheckResults(False, "empty file")
    return CheckResults(True)


# Map from metadata name to the check function.
CHECKERS = {
    "DIR_METADATA": check_content_dir_metadata,
    "OWNERS": check_content_owners,
    "README.md": check_content_readme_md,
}


def check_content(name: str, data: str) -> CheckResults:
    """Make sure metadata content is reasonable."""
    if name in CHECKERS:
        return CHECKERS[name](data)
    return CheckResults(True)


def check_metadata(path: Path, name: str) -> bool:
    """Check metadata in the overlay."""
    ret = True
    missing_overlays = MISSING_OVERLAYS[name]

    # If the file exists, we're all set!
    metadata_path = path / name
    if metadata_path.is_file():
        # Make sure it has actual content.
        results = check_content(name, metadata_path.read_text())
        if not results.passed:
            logging.error(
                "%s: %s: %s",
                path,
                name,
                results.message,
            )
            ret = False
        elif path.name in missing_overlays:
            logging.error(
                "%s: remove from MISSING_OVERLAYS_%s",
                path.name,
                name.upper(),
            )
            ret = False
    elif ret:
        ret = path.name in missing_overlays

    return ret


def check_overlay(path: Path) -> bool:
    """Check metadata in overlay |path|."""
    ret = True

    for metadata_name in METADATA:
        logging.debug("%s: checking %s", path, metadata_name)
        if not check_metadata(path, metadata_name):
            logging.error(
                "%s: missing %s",
                path.name,
                metadata_name,
            )
            ret = False

    return ret


def main(argv: List[str]) -> int:
    """Main function."""
    parser = commandline.ArgumentParser(description=__doc__)
    parser.add_argument("overlays", nargs="*", type=Path)
    opts = parser.parse_args(argv)

    if not opts.overlays:
        opts.overlays = DIR.glob("*-*/")

    ret = 0

    # Check for overlays that have been removed.
    for name in METADATA:
        missing_overlays = MISSING_OVERLAYS[name]
        for overlay in missing_overlays:
            if not (DIR / overlay).exists():
                logging.error(
                    "%s: remove from MISSING_OVERLAYS_%s", overlay, name.upper()
                )
                ret = 1

    for path in opts.overlays:
        if path.is_dir():
            if not check_overlay(path):
                ret = 1

    return ret


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
