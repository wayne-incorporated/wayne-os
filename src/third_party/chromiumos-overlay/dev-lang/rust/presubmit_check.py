#!/usr/bin/env python3
"""Does presubmit checks for Rust-like changes.

This is intended to be used by `repo`. For more information, please see
https://chromium.googlesource.com/chromiumos/repohooks/+/refs/heads/main/README.md.

Enforces the following rules:
  - If dev-lang/rust's ${PVR} moves, virtual/rust's must, as well.
  - If dev-lang/rust-host's ${PVR} moves, virtual/rust's must, as well.
  - dev-lang/rust-host, dev-lang/rust, and virtual/rust must remain in ${PV}
    lockstep.
"""

import os
import re
import subprocess
import sys
from typing import Dict, List, NamedTuple, Set


_DEV_LANG_RUST = 'dev-lang/rust/'
_DEV_LANG_RUST_HOST = 'dev-lang/rust-host/'
_VIRTUAL_RUST = 'virtual/rust/'
_ALL_RUST_DIRS = (_DEV_LANG_RUST, _DEV_LANG_RUST_HOST, _VIRTUAL_RUST)

# Contains lists of all ebuild names in dev-lang/rust, dev-lang/rust-host, and
# virtual/rust.
_RustEbuilds = NamedTuple(
    '_RustEbuildTree',
    [
        ('rust', List[str]),
        ('rust_host', List[str]),
        ('virtual', List[str]),
    ],
)

_Complaint = str


def _collect_rust_ebuilds(commit: str) -> _RustEbuilds:
    """Builds a _RustEbuilds object to represent the given commit."""
    ebuild_listings = {}
    for subdir in _ALL_RUST_DIRS:
        output = subprocess.check_output(
            ['git', 'ls-tree', '--name-only', '-z', commit, subdir],
            encoding='utf-8',
        )
        files = output.split('\0')
        ebuild_files = sorted(
            os.path.basename(x) for x in files if x.endswith('.ebuild'))
        assert ebuild_files, f'No ebuilds found in {subdir}'
        ebuild_listings[subdir] = ebuild_files

    return _RustEbuilds(
        rust=ebuild_listings[_DEV_LANG_RUST],
        rust_host=ebuild_listings[_DEV_LANG_RUST_HOST],
        virtual=ebuild_listings[_VIRTUAL_RUST],
    )


def _ensure_virtual_is_bumped_if_pvrs_change(
        previous: _RustEbuilds, current: _RustEbuilds) -> List[_Complaint]:
    """Ensures that the ${PV} of all packages are synced."""
    # In theory, this could be more precise and check what kinds of changes are
    # made. That said, it should be 'good enough' to simply look for any
    # filename change as a sign that another filename change must take place.
    need_virtual_bump = (previous.rust != current.rust
                         or previous.rust_host != current.rust_host)
    if need_virtual_bump and previous.virtual == current.virtual:
        return [
            "Detected Rust ebuild changes, but there's no virtual/rust update."
        ]

    return []


def _ensure_pvs_synced(current_ebuilds: _RustEbuilds) -> List[_Complaint]:
    """Ensures that the ${PV} of all packages are synced."""
    pv_regex = re.compile(
        r"""
        ^rust-(?:host-)?                 # Package name
        (\d\.\d+\.\d+)                   # (Captured) package version
        (?:_(?:alpha|beta|pre|rc|p)\d*)* # Version suffix
        (?:-r\d+)?                       # Optional revision
        \.ebuild$
        """,
        re.VERBOSE,
    )

    present_pvs: Dict[str, Set[str]] = {}
    for field in _RustEbuilds._fields:
        ebuilds = getattr(current_ebuilds, field)
        pvs = set()
        for ebuild in ebuilds:
            pv = pv_regex.match(ebuild)
            assert pv, f'No $PV regex match against {ebuild}'
            pvs.add(pv.group(1))
        present_pvs[field] = pvs

    all_pvs = set(x for pvs in present_pvs.values() for x in pvs)
    if all(pvs == all_pvs for pvs in present_pvs.values()):
        return []

    return [
        'For every Rusty $PV, there should be a package with that version in '
        'all of dev-lang/rust, dev-lang/rust-host, and virtual/rust. Detected '
        f'$PVs: {present_pvs}'
    ]


def _is_ebuild_file_in_rust_dir(file_path: str) -> bool:
    """Returns whether the param is an ebuild in a rust dir we should check."""
    return file_path.endswith('.ebuild') and any(
        file_path.startswith(x) for x in _ALL_RUST_DIRS)


def main():
    """Main function."""
    presubmit_files = os.environ.get('PRESUBMIT_FILES')
    if presubmit_files is None:
        sys.exit('Need a value for PRESUBMIT_FILES')

    presubmit_files = [x.strip() for x in presubmit_files.splitlines()]
    if not any(_is_ebuild_file_in_rust_dir(x) for x in presubmit_files):
        return

    presubmit_commit = os.environ.get('PRESUBMIT_COMMIT')
    if presubmit_commit is None:
        sys.exit('Need a value for PRESUBMIT_COMMIT')

    previous_ebuilds = _collect_rust_ebuilds(presubmit_commit + '~')
    current_ebuilds = _collect_rust_ebuilds(presubmit_commit)

    complaints = _ensure_virtual_is_bumped_if_pvrs_change(
        previous_ebuilds,
        current_ebuilds,
    )
    complaints += _ensure_pvs_synced(current_ebuilds)
    if not complaints:
        return

    for complaint in complaints:
        print(complaint, file=sys.stderr)
    sys.exit(1)


if __name__ == '__main__':
    main()
