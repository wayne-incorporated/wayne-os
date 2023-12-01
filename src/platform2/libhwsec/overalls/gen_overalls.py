#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2019 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Generate the overalls class and mock."""
from __future__ import print_function

import argparse
import datetime
import os
import re
import subprocess
import sys


_LICENSE_STRING = (
    """
// Copyright %d The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.
""".strip()
    % datetime.datetime.now().year
)

_OVERALLS_CLASS_DESCRIPTION = (
    "// |Overalls| wraps trousers API (including Tspi and Trspi family), with "
    'the wrapper API name being the trousers API names of which the first "T" '
    'replaced by "O". For example, |Overalls::Ospi_Context_Create| calls '
    "|Tspi_Context_Create|.\n//\n// The purpose of this wrapper class is to "
    "make trousers APIs to be mock-able so we can enable the callers of "
    "trouser to be unittested in googletest framework."
)


def _get_repo_related_path(path):
    """Replaces the path before 'src/platform2' by '//'."""
    path = os.path.realpath(path)
    token = "src/platform2"
    return "//" + token + path.split(token, 1)[1]


_THIS_FILE_PATH = _get_repo_related_path(__file__)
_THIS_FILE_DIR = os.path.dirname(os.path.realpath(__file__))
_PLATFORM2_DIR = _THIS_FILE_DIR.rsplit("libhwsec", 1)[0]
_TROUSERS_INCLUDE_DIR = (
    _PLATFORM2_DIR.rsplit("platform2", 1)[0]
    + "third_party/trousers/src/include"
)
_OUTPUT_SUBDIR = "libhwsec/overalls"

_GENERATOR_INFO = """
// This file is GENERATED and do not modify it manually.
// To reproduce the generation process, run %s with arguments as:
// %s
""".strip() % (
    _THIS_FILE_PATH,
    " ".join(sys.argv[1:]),
)

_EXTENDED_APIS = [
    (
        "TSS_RESULT",
        "Tspi_Context_SecureFreeMemory",
        [("TSS_HCONTEXT", "hContext"), ("BYTE*", "rgbMemory")],
    )
]


def build_filter(wd):
    """Builds a filter function based on used |trousers| APIs in under |wd|.

    Given the path |wd|, this function find out all the usage of |trousers| APIs
    using |git grep|. The content of |overalls| project itself is ignored.

    Args:
      wd: String of the woring directory where |git grep| is run.

    Returns:
      A filter function that returns |True| iff the usage is found by |git grep|.
    """
    cmd = [
        "git",
        "grep",
        "-oh",
        "-E",
        r"\b(T|O)r?spi_([a-zA-Z0-9]+_)?[a-zA-Z0-9_]+\b",
        ":(exclude)libhwsec/overalls/*",
    ]
    all_usages = subprocess.check_output(cmd, cwd=wd).decode("utf-8")
    all_usages_set = set()
    for usage in all_usages.splitlines():
        all_usages_set.add("T" + usage[1:])
    return lambda x: x in all_usages_set


def parse_trousers_input_args(s):
    """Parses Trspi family's input arguments.

    Given a string from of input arguments of a trousers API, the input arguments
    parsed into tokens and then convert to tuples. For example:
    "BYTE *s, unsigned *len"
    ->
    [("BYTE *", "s"), ("unsigned *", "len")]

    Args:
      s: String representation of the input arguments of a certain Trspi function.

    Returns:
      A list of tuples in form of (data type, variable name).
    """
    arr = s.split(",")
    for i, p in enumerate(arr):
        p = p.strip()
        # are stick with the variable name, e.g., UINT64 *offset, so the separator
        # could be last ' ' or '*'.
        pos = p.strip().rfind("*")
        if pos == -1:
            pos = p.rfind(" ")
            if pos == -1:
                pos = len(p)
        var_type, var_name = p[: pos + 1].strip(), p[pos + 1 :].strip()
        arr[i] = (var_type, var_name)
    return arr


def process_function_macro(args1, args2, arr2):
    """Parses Trspi family's input arguments for those implemented by macros.

    Args:
      args1: String representation of the input arguments of a certain the
        function as the caller.
      args2: String representation of the input arguments of a certain the
        function as the callee.
      arr2: List returned by |parse_trousers_input_args| when processing the
        callee.

    Returns:
      A list of tuples in form of (type, name).
    """
    tokens1 = args1.replace(" ", "").split(",")
    tokens2 = args2.replace(" ", "").split(",")
    return [arr2[tokens2.index(x)] for x in tokens1]


def process_trousers_h(input_string):
    """Processes the file content of trousers.h

    Parses the input file content and tokenize each function declaration into a
    3-tuple as shown in the following example:

    ***declaration***:
    BYTE *Trspi_Native_To_UNICODE(BYTE *string, unsigned *len);

    ***output***:
    ("BYTE *", "Trspi_Native_To_UNICODE",
    [("BYTE *", "s"), ("unsigned *", "len")])

    Note: the macro-style implementaions is also parsed into the same form.

    Args:
      input_string: the file content of trousers.h in a string.

    Returns:
      A list of 3-tuples where the data is in order of return type, function name,
      and a list of 2-tuple in form of (data type, variable name)
    """
    input_string = input_string.replace("\\\n", "").replace(",\n", ", ")
    r = re.compile(
        r"(void|TSS_RESULT|BYTE|char|UINT32|int)"
        r"([\s\*]+)Trspi_([\w\d_]+)\((.*)\);"
    )
    arr = []
    table = {}
    for m in r.finditer(input_string):
        return_type = (m.group(1) + m.group(2)).strip()
        name = "Trspi_" + m.group(3)
        arguments = parse_trousers_input_args(m.group(4))
        arr.append((return_type, name, arguments))
        table[name] = arr[-1]
    # Processes the macros.
    r = re.compile(
        r"#define\s+Trspi_([\w\d_]+)\((.*)\)\s+Trspi_([\w\d_]+)\((.*)\)"
    )

    for m in r.finditer(input_string):
        name = "Trspi_" + m.group(1)
        callee = table["Trspi_" + m.group(3)]
        return_type = callee[0]
        arguments = process_function_macro(m.group(2), m.group(4), callee[2])
        arr.append((return_type, name, arguments))

    # For self-test purpose.
    expected_api_counts = sum(
        1
        for x in input_string.splitlines()
        if " Trspi_" in x or " *Trspi_" in x
    )
    # Offset by 1 because there is also a strcut declaration starting from
    # "Trspi_". The offset should be adjusted accordingly if trousers.h changes.
    assert expected_api_counts == len(arr) + 1

    return arr


def process_tspi_h(input_string):
    """Process the file content of tspi.h

    Parses the input file content and tokenize each function declaration into a
    3-tuple as shown in the following example:

    ***declaration***:
    TSPICALL Tspi_Context_Create
    (
        TSS_HCONTEXT*       phContext                      // out
    );

    ***output***:
    ("TSS_RESULT", "Tspi_Context_Create", [("TSS_HCONTEXT*", "phContext")])

    Args:
      input_string: the file content of tspi.h in a string.

    Returns:
      A list of 3-tuples of return type, function name, a list of 2-tuple in form
      of (data type, variable name)
    """
    r = re.compile(r"^TSPICALL[\s\S]*?;", flags=re.M)
    arr = []
    for m in r.finditer(input_string):
        tokens = m.group(0).splitlines()
        name = tokens[0].split()[1]
        arguments = []
        for t in tokens[2:-1]:
            var_type, var_name = t.split()[:2]
            arguments.append((var_type, var_name.replace(",", "")))
        arr.append(("TSS_RESULT", name, arguments))

    # For self-test purpose.
    expected_api_counts = input_string.count("\nTSPICALL")
    assert expected_api_counts == len(arr)

    return arr


def tuples_to_wrapper_class(wrapper_class_name, functions):
    """Generates a wrapper class as a string from the parsed result of headers."""

    def to_virtual_member_function(return_type, name, arguments):
        """Generates the function declaraion from a parsed API information."""
        for i, a in enumerate(arguments):
            if not a[1]:
                arguments[i] = (a[0], "arg%d" % i)
        arguments_string = ",".join([" ".join(x) for x in arguments])
        inputs_string = ",".join([x[1] for x in arguments])
        caller_name = "O" + name[1:]
        callee_name = name
        return "virtual %s %s(%s){ return %s(%s); }" % (
            return_type,
            caller_name,
            arguments_string,
            callee_name,
            inputs_string,
        )

    member_functions = "\n".join(
        to_virtual_member_function(*x) for x in functions
    )
    ctor_and_dtor = "%s() = default;virtual ~%s() = default;" % (
        wrapper_class_name,
        wrapper_class_name,
    )
    return "%s\nclass %s {\npublic:\n%s\n%s\n};\n" % (
        _OVERALLS_CLASS_DESCRIPTION,
        wrapper_class_name,
        ctor_and_dtor,
        member_functions,
    )


def tuples_to_mock_class(wrapper_class_name, functions):
    """Generates a mock class as a string from the parsed result of headers."""

    def to_mock_method(return_type, name, arguments):
        """Generates the mock method from a parsed API information."""
        arguments_string = ",".join([" ".join(x) for x in arguments])
        arguments_string = ",".join([x[0] for x in arguments])
        # Falls back to CHECK(false) when too many arguments.
        if len(arguments) > 10:
            return (
                '%s %s(%s) override {CHECK(false) <<"too many arguments to be '
                'mockable.";return 0;}'
            ) % (return_type, name, arguments_string)
        return "MOCK_METHOD%d(%s,%s(%s));" % (
            len(arguments),
            name,
            return_type,
            arguments_string,
        )

    mock_methods = "\n".join(to_mock_method(*x) for x in functions)

    mock_class_name = "Mock" + wrapper_class_name
    ctor_and_dtor = "%s() = default;~%s() override = default;" % (
        mock_class_name,
        mock_class_name,
    )
    return "class %s:public %s {\npublic:\n%s\n%s\n};\n" % (
        mock_class_name,
        wrapper_class_name,
        ctor_and_dtor,
        mock_methods,
    )


def generate_source_code_string(include_guard, includes, namespaces, body):
    """Composes the inputs to a source file content.

    Args:
      include_guard: The string used as one-time includ guard.
      includes: The string of '#include ...' fields.
      namespaces: A iterable object that contains a series of namespaces.
      body: source code that put inside the nested namespaces depecified in the
        last argument.

    Returns:
      The file content string that is composed of the input parameters.
    """
    include_guard_begin = ""
    if include_guard:
        include_guard_begin = "#ifndef %s\n#define %s" % (
            include_guard,
            include_guard,
        )
    namespaces_begin = "\n".join("namespace %s {" % x for x in namespaces)
    include_guard_end = ""
    if include_guard:
        include_guard_end = "#endif  // %s" % (include_guard)
    namespaces_end = "\n".join("}  // namespace " + x for x in namespaces)
    strings = (
        _LICENSE_STRING,
        _GENERATOR_INFO,
        include_guard_begin,
        includes,
        namespaces_begin,
        body,
        namespaces_end,
        include_guard_end,
    )
    s = "\n\n".join(strings)
    return s + "\n"


def generate_source_code_file(
    file_path, include_guard, includes, namespaces, body
):
    """Call |generate_source_code_string| and write the content to a file."""
    content = generate_source_code_string(
        include_guard, includes, namespaces, body
    )
    with open(file_path, "w") as f:
        f.write(content)
    cmd = ["clang-format", "-sort-includes=0", "-i", file_path]
    subprocess.check_call(cmd)


def generate_include_guard(subdir, filename):
    """Generates the include guard for a C++ header.

    Args:
      subdir: the directory whare we put the generated file; it's relavtie to
        |platform2| repository.
      filename: the name of the file

    Returns:
      The macro used as the include guard.
    """
    subdir = subdir.strip("/\\")
    s = subdir.strip("/") + "_" + filename + "_"
    return s.replace("/", "_").replace(".", "_").upper()


def gen_arg_parser():
    """Creates the argument parser for the command line argument."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--filter-by-usage",
        action="store_true",
        help="if set, crawl the entire platform2 repo and "
        "generate code corrsponding to only used funtions.",
    )
    parser.add_argument(
        "--include-dir",
        type=str,
        default=_TROUSERS_INCLUDE_DIR,
        help="the directory containing trousers/trousers.h and tss/tspi.h. "
        "If not specified, the program locates "
        '"//src/third_party/trousers/src/include" in the same source tree of '
        "this python script.",
    )
    parser.add_argument(
        "--subdir",
        type=str,
        default=_OUTPUT_SUBDIR,
        help="the output directory relative to //src/platform2 where the "
        "generated headers are placed (in order to generate include guard)."
        'If not specified, the sub-directory is "%s"' % _OUTPUT_SUBDIR,
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=_THIS_FILE_DIR,
        help="the output directory of the generated files. "
        "If not specified, it is the same directory as this python script.",
    )
    return parser


def main(args):
    """The main function."""
    parser = gen_arg_parser()
    opts = parser.parse_args(args)

    trousers_dir = os.path.join(os.path.abspath(opts.include_dir), "trousers")
    trousers_h_path = os.path.join(trousers_dir, "trousers.h")
    with open(trousers_h_path, "r") as f:
        input_string = f.read()
    result = process_trousers_h(input_string)
    tss_dir = os.path.join(os.path.abspath(opts.include_dir), "tss")
    tss_h_path = os.path.join(tss_dir, "tspi.h")
    with open(tss_h_path, "r") as f:
        input_string = f.read()
    result += process_tspi_h(input_string)
    result += _EXTENDED_APIS

    if opts.filter_by_usage:
        print("filtering by usage...")
        func = build_filter(_PLATFORM2_DIR)
        old_size = len(result)
        result = [x for x in result if func(x[1])]
        new_size = len(result)
        print(
            "pruning %d out of %d APIs and new result has %d APIs"
            % (old_size - new_size, old_size, new_size)
        )

    include_guard = generate_include_guard(opts.subdir, "overalls.h")
    includes = (
        "#include <trousers/trousers.h>\n#include <trousers/tss.h>\n\n"
        '#include "libhwsec/tss_utils/extended_apis.h"'
    )
    namespaces = ("hwsec", "overalls")
    file_path = os.path.join(opts.output_dir, "overalls.h")
    generate_source_code_file(
        file_path,
        include_guard,
        includes,
        namespaces,
        tuples_to_wrapper_class("Overalls", result),
    )

    include_guard = generate_include_guard(opts.subdir, "mock_overalls.h")
    includes = (
        "#include <base/logging.h>\n#include <gmock/gmock.h>\n#include "
        '"libhwsec/overalls/overalls.h"'
    )
    namespaces = ("hwsec", "overalls")
    file_path = os.path.join(opts.output_dir, "mock_overalls.h")
    generate_source_code_file(
        file_path,
        include_guard,
        includes,
        namespaces,
        tuples_to_mock_class(
            "Overalls", [(x[0], "O" + x[1][1:], x[2]) for x in result]
        ),
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
