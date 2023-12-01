#!/usr/bin/env python3
# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Basic functionality tests for llvm-profdata."""

import os
import subprocess
import unittest
from pathlib import Path

# Example taken from LLVM's llvm/Transforms/SampleProfile/Inputs/summary.prof
_EXAMPLE_PROFILE_DATA = """
bar:100:3
 1: 100
foo:200:1
 1: 200
baz:600:1
 1: 0
 2: 300
 1: bar:300
  1: 300
"""

# A clang program that doesn't _completely_ match the profile above, but should
# prompt clang to at least load the entries from it.
_CLANG_PROGRAM = """
int foo(int i) {
  if (i)
    return 1;
  return 2;
}
int bar(int i) {
  if (i)
    return 1;
  return 2;
}
int baz(int i) {
  if (i)
    return 1;
  return 2;
}
"""


class Test(unittest.TestCase):
    """Tests for llvm-profdata."""

    def create_test_case_tempdir(self) -> Path:
        """Creates a tempdir unique to the given test."""
        t = os.getenv('T')
        assert t, '$T should be set'
        dir_path = Path(t) / 'llvm-profdata-test' / self.id()
        dir_path.mkdir(parents=True, exist_ok=False)
        # Don't worry about cleaning this up; portage will handle it if
        # appropriate.
        return dir_path

    def _test_conversion_succeeds(self, conversion_flag):
        """Tests that a given profile format seems to work.

        Work, in this case, means that we can convert to it from a text
        profile, and that clang can parse the result.
        """
        tempdir = self.create_test_case_tempdir()
        input_file = tempdir / 'input.proftxt'
        output_file = tempdir / 'converted-output'
        input_file.write_text(_EXAMPLE_PROFILE_DATA, encoding='utf-8')

        # Unfortunately, testing for roundtripability doesn't work with some of
        # the formats we care about (e.g., extbinary). Just be sure that
        # llvm-profdata can emit a profile in a suitable format, and that clang
        # can _load_ it.
        subprocess.run(
            [
                'llvm-profdata',
                'merge',
                '--sample',
                conversion_flag,
                f'--output={output_file}',
                str(input_file),
            ],
            check=True,
        )

        cc = os.getenv('CC')
        assert cc, 'need $CC set'
        subprocess.run(
            [
                cc,
                '-c',
                '-O2',
                f'-fprofile-sample-use={output_file}',
                '-x',
                'c',
                '-',
                '-o',
                '/dev/null',
            ],
            check=True,
            encoding='utf-8',
            input=_CLANG_PROGRAM,
            stderr=subprocess.DEVNULL,
        )

    def test_text_conversion_works(self):
        """Tests that text profile conversion works.

        In theory, it's a nop, but it's cheap to just be sure.
        """
        self._test_conversion_succeeds('--text')

    def test_binary_conversion_works(self):
        """Tests that regular binary profile conversion works."""
        self._test_conversion_succeeds('--binary')

    def test_extbinary_conversion_works(self):
        """Tests that extbinary profile conversion works."""
        self._test_conversion_succeeds('--extbinary')


if __name__ == '__main__':
    unittest.main()
