#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""A command-line tool to generate C++ source files that embed other files."""

import argparse
import os
import re
import subprocess
import sys


COPYRIGHT = """/*
 * Copyright 2021 The ChromiumOS Authors
 * Use of this source code is governed by a BSD-style license that can be
 * found in the LICENSE file.
 */"""

CC_HEADER_FILE = """{copyright}

#ifndef {header_guard}
#define {header_guard}

#include "common/embed_file_toc.h"

namespace {namespace} {{

cros::EmbeddedFileToc Get{toc_name}Toc();

}}  // namespace {namespace}

#endif // {header_guard}"""

CC_CONTENT_ENTRY = """
const char {key}[] = R"cc_embed_data({value})cc_embed_data";
"""

CC_SOURCE_FILE_HEADER = """{copyright}

#include "{header_file}"

namespace {namespace} {{
"""

CC_TOC_GETTER_UPPER = """
cros::EmbeddedFileToc Get{toc_name}Toc() {{
  std::map<std::string, cros::EmbeddedFileEntry> toc;
"""

CC_TOC_ENTRY = """
  toc.insert(
      {{"{key}", cros::EmbeddedFileEntry({var_name}, sizeof({var_name}))}});"""

CC_TOC_GETTER_LOWER = """
  return cros::EmbeddedFileToc(std::move(toc));
}
"""

CC_SOURCE_FILE_FOOTER = """
}}  // namespace {namespace}
"""


def ToCamelCase(in_str: str) -> str:
    return "".join(s.title() for s in in_str.split("_"))


def ToVariableName(in_str: str) -> str:
    result = re.sub(r"\W+", r"_", in_str)
    return result.lower()


def ToCameraIncludePath(in_path: str, base_path: str) -> str:
    return os.path.relpath(in_path, os.path.join(base_path, "camera"))


def ToHeaderGuard(in_path: str, base_path: str) -> str:
    header_guard = os.path.relpath(in_path, base_path)
    header_guard = re.sub(r"\W+", r"_", header_guard)
    header_guard = header_guard.upper().rstrip("_")
    header_guard += "_"
    return header_guard


def ClangFormatFile(file_path: str):
    subprocess.check_call(["/usr/bin/clang-format", "-i", file_path])


def PrepareSourceContent(file_path: str):
    if not os.path.exists(file_path):
        raise IOError("Cannot find source file: %s" % (file_path))

    with open(file_path, "r") as f:
        return f.read()


def CreateHeaderFile(args):
    with open(args.output_header_file, "w+") as f:
        f.write(
            CC_HEADER_FILE.format(
                copyright=COPYRIGHT,
                header_guard=ToHeaderGuard(
                    args.output_header_file, args.target_base_path
                ),
                namespace=args.namespace,
                toc_name=ToCamelCase(args.toc_name),
            )
        )

    ClangFormatFile(args.output_header_file)


def CreateCcFile(args, toc: dict):
    with open(args.output_cc_file, "w+") as f:
        f.write(
            CC_SOURCE_FILE_HEADER.format(
                copyright=COPYRIGHT,
                header_file=ToCameraIncludePath(
                    args.output_header_file, args.target_base_path
                ),
                namespace=args.namespace,
            )
        )

        for k, v in toc.items():
            f.write(CC_CONTENT_ENTRY.format(key=ToVariableName(k), value=v))

        f.write(CC_TOC_GETTER_UPPER.format(toc_name=ToCamelCase(args.toc_name)))

        for k, v in toc.items():
            f.write(CC_TOC_ENTRY.format(key=k, var_name=ToVariableName(k)))

        f.write(CC_TOC_GETTER_LOWER)

        f.write(
            CC_SOURCE_FILE_FOOTER.format(
                namespace=args.namespace, toc_name=args.toc_name
            )
        )

    ClangFormatFile(args.output_cc_file)


def ParseArguments(argv):
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--source-files",
        type=str,
        required=True,
        help="a list of comma separated source files to embed",
    )
    parser.add_argument(
        "--output-header-file",
        type=str,
        required=True,
        help="the output header file name",
    )
    parser.add_argument(
        "--output-cc-file",
        type=str,
        required=True,
        help="the output cc file name",
    )
    parser.add_argument(
        "--target-base-path",
        type=str,
        default="/mnt/host/source/src/platform2",
        help=(
            "base filepath to where the generated files will "
            "be written into (default: %(default)s)"
        ),
    )
    parser.add_argument(
        "--toc-name", type=str, required=True, help="the TOC getter name"
    )
    parser.add_argument(
        "--namespace",
        type=str,
        default="cros",
        help=("C++ namespace for the generated code " "(default: %(default)s)"),
    )

    return parser.parse_args(argv)


def main(argv: list) -> int:
    args = ParseArguments(argv)
    toc = {}
    for source_file in args.source_files.split(","):
        index = os.path.basename(source_file)
        if index in toc:
            raise KeyError("Duplicated source file: %s" % (source_file))
        toc[index] = PrepareSourceContent(source_file)

    CreateHeaderFile(args)
    CreateCcFile(args, toc)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
