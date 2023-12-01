#!/usr/bin/env python3
# # Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Verify syscall in seccomp policy files."""

from collections import namedtuple
from pathlib import Path
import sys

from chromite.lib import commandline


SeccompLine = namedtuple("SeccompLine", ["line_number", "line", "value"])


def ParseSeccompValue(seccomp_line):
    return set([seccomp.strip() for seccomp in seccomp_line.split("||")])


def ParseSeccompAndReturnParseError(
    filename, required_syscalls, denied_syscalls
):
    seccomp = {}
    parse_error = ""
    with open(filename, "r", encoding="utf-8") as f:
        line_buffer = ""
        for idx, current_line in enumerate(f.readlines()):
            line_buffer += current_line
            if line_buffer.endswith("\\\n"):
                line_buffer = line_buffer[:-2]
                continue
            line = line_buffer
            line_buffer = ""

            if line.isspace() or line.startswith("#"):
                continue
            tokens = line.split(":", 1)
            if len(tokens) != 2:
                parse_error += (
                    f'{filename}:{idx + 1}: error: cannot split by ":"\n{line}'
                )
                continue
            syscall = tokens[0].strip()
            if syscall in seccomp:
                parse_error += (
                    f'{filename}:{idx + 1}: error: duplicated syscalls"\n{line}'
                )
                parse_error += (
                    f"{filename}:{seccomp[syscall].line_number}: "
                    f'first defined here"\n{seccomp[syscall].line}'
                )
                continue
            seccomp[syscall] = SeccompLine(idx + 1, line, tokens[1].strip())
        if line_buffer:
            parse_error += f'{filename}: unexpected termination "\\"\n'

    missing_syscalls = ""
    for syscall, value in required_syscalls:
        if syscall not in seccomp:
            missing_syscalls += f"{syscall}: {value}\n"
            continue
        if seccomp[syscall].value == "1":
            continue
        if value == "1":
            parse_error += (
                f"{filename}:{seccomp[syscall].line_number}: the value of "
                f'required syscall should be "1"\n{seccomp[syscall].line}'
            )
            continue
        required_values = ParseSeccompValue(value)
        if not required_values.issubset(
            ParseSeccompValue(seccomp[syscall].value)
        ):
            parse_error += (
                f"{filename}:{seccomp[syscall].line_number}: the value of "
                f"required syscall should include {required_values}\n"
                f"{seccomp[syscall].line}"
            )
            continue
    if missing_syscalls:
        parse_error += (
            f"{filename}: missing following required syscall:\n"
            f"{missing_syscalls}"
        )

    for syscall in denied_syscalls:
        if syscall in seccomp:
            parse_error += (
                f"{filename}:{seccomp[syscall].line_number}: "
                f"denied syscall\n"
                f"{seccomp[syscall].line}"
            )
            continue

    return parse_error


def seccomp_pair(arg):
    tokens = arg.split(":", 1)
    if len(tokens) == 1:
        return [tokens[0].strip(), "1"]
    return [tokens[0].strip(), tokens[1].strip()]


def GetParser():
    """Returns an argument parser."""
    parser = commandline.ArgumentParser(description=__doc__)
    parser.add_argument("--seccomp", required=True, help="Seccomp filename.")
    parser.add_argument(
        "--output",
        required=True,
        help="Output filename for the check result (for gn to check timestamp).",
    )
    parser.add_argument(
        "--required-syscalls",
        default=[],
        action="append",
        type=seccomp_pair,
        help=(
            'Syscalls which are required. The value of syscall should be "1" if'
            "no required values are specified. To specify the required values "
            'of syscall, the format is "SYSCALL: VALUE_1 || ... || VALUE_N".'
        ),
    )
    parser.add_argument(
        "--denied-syscalls",
        default=[],
        action="append",
        help="Syscalls which are denied.",
    )
    return parser


def main(argv):
    parser = GetParser()
    opts = parser.parse_args(argv)
    opts.Freeze()

    parse_error = ParseSeccompAndReturnParseError(
        opts.seccomp, opts.required_syscalls, opts.denied_syscalls
    )
    if parse_error:
        sys.stderr.write(parse_error)
        return 1
    Path(opts.output).touch()
    return 0


if __name__ == "__main__":
    commandline.ScriptWrapperMain(lambda _: main)
