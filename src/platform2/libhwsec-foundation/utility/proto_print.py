#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright 2015 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""A C++ code generator for printing protobufs which use the LITE_RUNTIME.

Normally printing a protobuf would be done with Message::DebugString(). However,
this is not available when using only MessageLite. This script generates code to
emulate Message::DebugString() without using reflection. The input must be a
valid .proto file.

Usage: proto_print.py [--package-dir=pac] [--subdir=foo] <bar.proto>

Files named print_bar_proto.h and print_bar_proto.cc will be created in the
current working directory.
"""

from __future__ import print_function

import argparse
import collections
from datetime import date
import os
import re
import subprocess
import sys


# Holds information about a protobuf message field.
#
# Attributes:
#   repeated: Whether the field is a repeated field.
#   type_: The type of the field. E.g. int32.
#   name: The name of the field.
Field = collections.namedtuple("Field", "repeated type_ name proto3")


class Message(object):
    """Holds information about a protobuf message.

    Attributes:
        name: The name of the message.
        fields: A list of Field tuples.
    """

    def __init__(self, name):
        """Initializes a Message instance.

        Args:
            name: The protobuf message name.
        """
        self.name = name
        self.fields = []

    def AddField(self, attribute, field_type, field_name, proto3):
        """Adds a new field to the message.

        Args:
            attribute: This should be 'optional', 'required', or 'repeated'.
            field_type: The type of the field. E.g. int32.
            field_name: The name of the field.
            proto3: The field is proto3 style or not.
        """
        self.fields.append(
            Field(
                repeated=attribute == "repeated",
                type_=field_type,
                name=field_name,
                proto3=proto3,
            )
        )


class Enum(object):
    """Holds information about a protobuf enum.

    Attributes:
        name: The name of the enum.
        values: A list of enum value names.
    """

    def __init__(self, name):
        """Initializes a Enum instance.

        Args:
            name: The protobuf enum name.
        """
        self.name = name
        self.values = []

    def AddValue(self, value_name):
        """Adds a new value to the enum.

        Args:
            value_name: The name of the value.
        """
        self.values.append(value_name)


class Oneof(object):
    """Holds information about a protobuf Oneof.

    Attributes:
        name: The name of the OnoOf.
    """

    def __init__(self, name):
        """Initializes a OnoOf instance.

        Args:
            name: The protobuf OnoOf name.
        """
        self.name = name


def ParseProto(input_file):
    """Parses a proto file and returns a tuple of parsed information.

    Args:
        input_file: The proto file to parse.

    Returns:
        A tuple in the form (package, imports, messages, enums) where
        package: A string holding the proto package.
        imports: A list of strings holding proto imports.
        messages: A list of Message objects; one for each message in the proto.
        enums: A list of Enum objects; one for each enum in the proto.
    """
    package = ""
    imports = []
    messages = []
    enums = []
    current_message_stack = []
    current_enum = None
    current_oneof = None
    package_re = re.compile(r"package\s+([.\w]+);")
    import_re = re.compile(r'import\s+"([\w]*/)*(\w+).proto";')
    message_re = re.compile(r"message\s+(\w+)\s*{")
    field_re = re.compile(r"(optional|required|repeated)\s+(\w+)\s+(\w+)\s*=")
    field_re3 = re.compile(r"(|repeated\s+)([.\w]+)\s+(\w+)\s*=")
    enum_re = re.compile(r"enum\s+(\w+)\s*{")
    enum_value_re = re.compile(r"(\w+)\s*=")
    oneof_re = re.compile(r"oneof\s+(\w+)\s*{")
    for line in input_file:
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        msg_match = message_re.search(line)
        enum_match = enum_re.search(line)
        oneof_match = oneof_re.search(line)
        field_match = field_re.search(line)
        field_match3 = field_re3.search(line)
        package_match = package_re.search(line)
        import_match = import_re.search(line)
        # Look for a message definition.
        if msg_match:
            prefix = ""
            if current_message_stack:
                prefix = (
                    "::".join([m.name for m in current_message_stack]) + "::"
                )
            current_message_stack.append(Message(prefix + msg_match.group(1)))
        elif current_message_stack and oneof_match:
            if current_oneof:
                raise Exception("Unsupported nested oneof")
            # TODO(b/220231404): Support the printing of oneof field.
            current_oneof = Oneof(prefix + oneof_match.group(1))
        # Look for a message field definition.
        elif current_message_stack and field_match:
            current_message_stack[-1].AddField(
                field_match.group(1),
                field_match.group(2),
                field_match.group(3),
                False,
            )
        elif (
            current_message_stack
            and field_match3
            and field_match3.group(2) != "option"
        ):
            current_message_stack[-1].AddField(
                field_match3.group(1).strip(),
                field_match3.group(2),
                field_match3.group(3),
                True,
            )
        elif enum_match:
            prefix = ""
            if current_message_stack:
                prefix = "_".join([m.name for m in current_message_stack]) + "_"
            current_enum = Enum(prefix + enum_match.group(1))
            continue
        # Look for an enum value.
        elif current_enum:
            match = enum_value_re.search(line)
            if match:
                prefix = ""
                if current_message_stack:
                    prefix = current_enum.name + "_"
                current_enum.AddValue(prefix + match.group(1))
        # Look for a package statement.
        elif package_match:
            package = package_match.group(1)
        # Look for an import statement.
        elif import_match:
            imports.append(import_match.group(2))

        # Close off the current scope. Enums first because they can't be nested.
        if line[-1] == "}":
            if current_enum:
                enums.append(current_enum)
                current_enum = None
            elif current_oneof:
                # TODO(b/220231404): Support the printing of oneof field.
                current_oneof = None
            elif current_message_stack:
                messages.append(current_message_stack.pop())
            else:
                raise Exception("Closing unknown scope")

    # Make sure we parse the proto file correctly.
    if current_enum:
        raise Exception(f'The current_enum "{current_enum.name}" is not empty')

    if current_oneof:
        raise Exception(
            f'The current_oneof "{current_oneof.name}" is not empty'
        )

    if current_message_stack:
        name_stack = [msg.name for msg in current_message_stack]
        raise Exception(f"The current_message_stack {name_stack} is not empty")

    return package, imports, messages, enums


def GenerateFileHeaders(
    proto_name,
    package,
    imports,
    subdir,
    proto_include_override,
    header_file_name,
    header_file,
    impl_file,
    package_dir,
):
    """Generates and prints file headers.

    Args:
        proto_name: The name of the proto file.
        package: The protobuf package.
        imports: A list of imported protos.
        subdir: The --subdir arg.
        proto_include_override: Include directory override for the #include
                        statement in generated code
        header_file_name: The header file name.
        header_file: The header file handle, open for writing.
        impl_file: The implementation file handle, open for writing.
        package_dir: The package directory.
    """
    if subdir:
        guard_name = "%s_%s_PRINT_%s_PROTO_H_" % (
            package_dir.upper(),
            subdir.upper(),
            proto_name.upper(),
        )
        package_with_subdir = "%s/%s" % (package_dir, subdir)
    else:
        guard_name = "%s_PRINT_%s_PROTO_H_" % (
            package_dir.upper(),
            proto_name.upper(),
        )
        package_with_subdir = package_dir
    proto_include_dir = package_with_subdir
    if proto_include_override is not None:
        proto_include_dir = proto_include_override
    namespace = package.replace(".", "::")
    includes = "\n".join(
        [
            '#include "%(package_with_subdir)s/print_%(import)s_proto.h"'
            % {
                "package_with_subdir": package_with_subdir,
                "import": current_import,
            }
            for current_import in imports
        ]
    )
    header = """\
// Copyright %(year)s The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// THIS CODE IS GENERATED.
// Generated with command:
// %(cmd)s

#ifndef %(guard_name)s
#define %(guard_name)s

#include <string>

#include <brillo/brillo_export.h>

#include "%(proto_include_dir)s/%(proto)s.pb.h"

namespace %(namespace)s {
""" % {
        "year": date.today().year,
        "guard_name": guard_name,
        "namespace": namespace,
        "proto": proto_name,
        "proto_include_dir": proto_include_dir,
        "cmd": " ".join(sys.argv),
    }
    impl = """\
// Copyright %(year)s The ChromiumOS Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// THIS CODE IS GENERATED.
// Generated with command:
// %(cmd)s

#include "%(package_with_subdir)s/%(header_file_name)s"

#include <inttypes.h>

#include <string>

#include <base/strings/string_number_conversions.h>
#include <base/strings/stringprintf.h>

%(includes)s

namespace %(namespace)s {
""" % {
        "year": date.today().year,
        "namespace": namespace,
        "package_with_subdir": package_with_subdir,
        "header_file_name": header_file_name,
        "includes": includes,
        "cmd": " ".join(sys.argv),
    }

    header_file.write(header)
    impl_file.write(impl)


def GenerateFileFooters(
    proto_name, package, subdir, header_file, impl_file, package_dir
):
    """Generates and prints file footers.

    Args:
        proto_name: The name of the proto file.
        package: The protobuf package.
        subdir: The --subdir arg.
        header_file: The header file handle, open for writing.
        impl_file: The implementation file handle, open for writing.
        package_dir: The package directory.
    """
    namespace = package.replace(".", "::")
    if subdir:
        guard_name = "%s_%s_PRINT_%s_PROTO_H_" % (
            package_dir.upper(),
            subdir.upper(),
            proto_name.upper(),
        )
    else:
        guard_name = "%s_PRINT_%s_PROTO_H_" % (
            package_dir.upper(),
            proto_name.upper(),
        )
    header = """

}  // namespace %(namespace)s

#endif  // %(guard_name)s
""" % {
        "guard_name": guard_name,
        "namespace": namespace,
    }
    impl = """
}  // namespace %(namespace)s
""" % {
        "namespace": namespace
    }

    header_file.write(header)
    impl_file.write(impl)


def GenerateEnumPrinter(enum, header_file, impl_file):
    """Generates and prints a function to print an enum value.

    Args:
        enum: An Enum instance.
        header_file: The header file handle, open for writing.
        impl_file: The implementation file handle, open for writing.
    """
    declare = """
std::string GetProtoDebugStringWithIndent(%(name)s value, int indent_size);
BRILLO_EXPORT std::string GetProtoDebugString(%(name)s value);""" % {
        "name": enum.name
    }
    define_begin = """
std::string GetProtoDebugString(%(name)s value) {
  return GetProtoDebugStringWithIndent(value, 0);
}

std::string GetProtoDebugStringWithIndent(%(name)s value, int indent_size) {
""" % {
        "name": enum.name
    }
    define_end = """
  return "<unknown>";
}
"""
    condition = """
  if (value == %(value_name)s) {
    return "%(value_name)s";
  }"""

    header_file.write(declare)
    impl_file.write(define_begin)
    for value_name in enum.values:
        impl_file.write(condition % {"value_name": value_name})
    impl_file.write(define_end)


def GenerateMessagePrinter(message, header_file, impl_file):
    """Generates and prints a function to print a message.

    Args:
        message: A Message instance.
        header_file: The header file handle, open for writing.
        impl_file: The implementation file handle, open for writing.
    """
    declare = """
std::string GetProtoDebugStringWithIndent(const %(name)s& value,
                                          int indent_size);
BRILLO_EXPORT std::string GetProtoDebugString(const %(name)s& value);""" % {
        "name": message.name
    }
    define_begin = """
std::string GetProtoDebugString(const %(name)s& value) {
  return GetProtoDebugStringWithIndent(value, 0);
}

std::string GetProtoDebugStringWithIndent(const %(name)s& value,
                                          int indent_size) {
  std::string indent(indent_size, ' ');
  std::string output = base::StringPrintf("[%%s] {\\n",
                                          value.GetTypeName().c_str());
""" % {
        "name": message.name
    }
    define_end = """
  output += indent + "}\\n";
  return output;
}
"""
    singular_field = """
  if (value.has_%(name)s()) {
    output += indent + "  %(name)s: ";
    base::StringAppendF(&output, %(format)s);
    output += "\\n";
  }"""
    proto3_singular_field = """
  output += indent + "  %(name)s: ";
  base::StringAppendF(&output, %(format)s);
  output += "\\n";
  """
    repeated_field = """
  output += indent + "  %(name)s: {";
  for (int i = 0; i < value.%(name)s_size(); ++i) {
    if (i > 0) {
      base::StringAppendF(&output, ", ");
    }
    base::StringAppendF(&output, %(format)s);
  }
  output += "}\\n";"""
    singular_field_get = "value.%(name)s()"
    repeated_field_get = "value.%(name)s(i)"
    formats = {
        "bool": '"%%s", %(value)s ? "true" : "false"',
        "int32": '"%%" PRId32, %(value)s',
        "int64": '"%%" PRId64, %(value)s',
        "uint32": '"%%" PRIu32 " (0x%%08" PRIX32 ")", %(value)s, %(value)s',
        "uint64": '"%%" PRIu64 " (0x%%016" PRIX64 ")", %(value)s, %(value)s',
        "string": '"%%s", %(value)s.c_str()',
        "bytes": """"%%s", base::HexEncode(%(value)s.data(),
                                         %(value)s.size()).c_str()""",
    }
    subtype_format = (
        '"%%s", GetProtoDebugStringWithIndent(%(value)s, '
        "indent_size + 2).c_str()"
    )

    header_file.write(declare)
    impl_file.write(define_begin)
    for field in message.fields:
        if field.repeated:
            value_get = repeated_field_get % {"name": field.name}
            field_code = repeated_field
        elif field.proto3:
            value_get = singular_field_get % {"name": field.name}
            field_code = proto3_singular_field
        else:
            value_get = singular_field_get % {"name": field.name}
            field_code = singular_field
        if field.type_ in formats:
            value_format = formats[field.type_] % {"value": value_get}
        else:
            value_format = subtype_format % {"value": value_get}
        impl_file.write(
            field_code % {"name": field.name, "format": value_format}
        )
    impl_file.write(define_end)


def FormatFile(filename):
    subprocess.call(["clang-format", "-i", "-style=Chromium", filename])


def main():
    parser = argparse.ArgumentParser(description="print proto code generator")
    parser.add_argument(
        "--package-dir",
        default="",
        help=("Override for the package directory name"),
    )
    parser.add_argument(
        "--subdir",
        default="",
        help=(
            "The subdirectory under which the generated "
            + "file will reside in"
        ),
    )
    parser.add_argument(
        "--proto-include-override",
        default=None,
        help=(
            "Override for the include path of *.pb.h in" + "generated header"
        ),
    )
    parser.add_argument(
        "--output-dir", default=".", help=("The output directory")
    )
    parser.add_argument("input_files", nargs="*")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    for input_path in args.input_files:
        with open(input_path) as input_file:
            package, imports, messages, enums = ParseProto(input_file)
        package_dir = package
        if args.package_dir != "":
            package_dir = args.package_dir
        proto_name = os.path.basename(input_path).rsplit(".", 1)[0]
        header_file_name = "print_%s_proto.h" % proto_name
        impl_file_name = "print_%s_proto.cc" % proto_name
        header_file_path = os.path.join(args.output_dir, header_file_name)
        impl_file_path = os.path.join(args.output_dir, impl_file_name)
        with open(header_file_path, "w") as header_file:
            with open(impl_file_path, "w") as impl_file:
                GenerateFileHeaders(
                    proto_name,
                    package,
                    imports,
                    args.subdir,
                    args.proto_include_override,
                    header_file_name,
                    header_file,
                    impl_file,
                    package_dir,
                )
                for enum in enums:
                    GenerateEnumPrinter(enum, header_file, impl_file)
                for message in messages:
                    GenerateMessagePrinter(message, header_file, impl_file)
                GenerateFileFooters(
                    proto_name,
                    package,
                    args.subdir,
                    header_file,
                    impl_file,
                    package_dir,
                )
        FormatFile(header_file_path)
        FormatFile(impl_file_path)


if __name__ == "__main__":
    main()
