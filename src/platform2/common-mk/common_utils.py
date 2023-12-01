# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Common functions used from multiple files."""

# Usually we should use cros_build_lib.RunCommand over subprocess.check_output
# to avoid possible issues in subprocess. Here we use subprocess exceptionally,
# because the usage is simple enough, and lower overhead is important as it
# being called about ten times per each ebuild. See crbug.com/868820 for the
# time comparison.
import subprocess


def parse_shell_args(s):
    """Parse |s| representing shell arguments (e.g. C++ flags) as a list.

    For example, '''-DFOO=a -DBAR='"b c"' -DBAZ="d e f"''' becomes
    ['-DFOO=a', '-DBAR="b c"', '-DBAZ=d e f'].
    For GN, strings to be passed to the shell must have been parsed, otherwise
    they are escaped by GN when emitting ninja files.
    """
    # The dummy variable prevents the first value in s from being interpreted as
    # a flag for echo. IFS is set to separate $* with newlines.
    output = subprocess.check_output(
        ['eval "set -- dummy $0"; IFS=$\'\\n\'; printf "%s" "$*"', s],
        shell=True,
        encoding="utf-8",
    )
    return output.splitlines()[1:]
