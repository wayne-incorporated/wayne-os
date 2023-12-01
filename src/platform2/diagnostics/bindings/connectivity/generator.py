#!/usr/bin/env python3
# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Generate mojo connectivity test code."""

import json
import os
from pathlib import Path

# pylint: disable=import-error, no-name-in-module
import jinja2
from generators import mojom_cpp_generator
from mojom.generate import generator as mojom_generator
from mojom.generate import module as mojom_module

# pylint: enable=import-error, no-name-in-module

from chromite.lib import commandline

TEMPLATES_PATH = Path(Path(os.path.realpath(__file__)).parent, "templates")


class Generator:
    """Generates bindings code for c++."""

    def __init__(self, mojom, mojo_root, output_dir, generator_overrides):
        self._output_dir = output_dir
        self._mojom = os.path.relpath(mojom, mojo_root)
        self._generator_overrides = generator_overrides

        self._module = None
        self._LoadModule()

        self._env = None
        self._SetUpEnv()

    def _LoadModule(self):
        module_path = Path(self._output_dir, f"{self._mojom}-module")
        with module_path.open("rb") as f:
            self._module = mojom_module.Module.Load(f)
        self._module.Stylize(mojom_generator.Stylizer())

    def _GetFullMojomNameForKind(self, kind):
        return self._env.filters["get_full_mojom_name_for_kind"](kind)

    def _IsGeneratorOverrideKind(self, kind):
        return (
            hasattr(kind, "name")
            and self._GetFullMojomNameForKind(kind) in self._generator_overrides
        )

    def _GetGeneratorOverrideType(self, kind):
        if not self._IsGeneratorOverrideKind(kind):
            return None
        return self._generator_overrides[self._GetFullMojomNameForKind(kind)][
            "generator_typename"
        ]

    def _SetUpEnv(self):
        self._env = jinja2.Environment(
            loader=jinja2.FileSystemLoader(TEMPLATES_PATH)
        )
        generator = mojom_cpp_generator.Generator(self._module)
        self._env.filters.update(generator.GetFilters())
        self._env.filters.update(
            {
                "generator_override_type": self._GetGeneratorOverrideType,
            }
        )
        self._env.tests.update(
            {
                "PendingRemoteKind": mojom_module.IsPendingRemoteKind,
                "PendingReceiverKind": mojom_module.IsPendingReceiverKind,
                "StructKind": mojom_module.IsStructKind,
                "UnionKind": mojom_module.IsUnionKind,
                "EnumKind": mojom_module.IsEnumKind,
                "ArrayKind": mojom_module.IsArrayKind,
                "MapKind": mojom_module.IsMapKind,
                "GenericHandleKind": mojom_module.IsGenericHandleKind,
                "GeneratorOverrideKind": self._IsGeneratorOverrideKind,
            }
        )

    def _GenerateFile(self, suffix, args):
        data = self._env.get_template(f"{suffix}.j2").render(**args)
        output_file = Path(self._output_dir, f"{self._mojom}-{suffix}")
        output_file.write_text(data)

    def Generate(self):
        extra_headers = []
        for override in self._generator_overrides.values():
            extra_headers += override["generator_headers"]
        args = {
            "module": self._module,
            "namespaces_as_array": self._module.mojom_namespace.split("."),
            "extra_headers": extra_headers,
        }
        self._GenerateFile("connectivity-forward.h", args)
        self._GenerateFile("connectivity.h", args)
        self._GenerateFile("connectivity.cc", args)


def Generate(mojoms, mojo_root, output_dir, generator_overrides_files):
    """Parses arguments and generates bindings code for c++."""
    generator_overrides = {}
    for f in generator_overrides_files:
        override = json.loads(Path(f).read_bytes())
        generator_overrides.update(override.get("c++", {}))

    for mojom in mojoms:
        Generator(mojom, mojo_root, output_dir, generator_overrides).Generate()


def GetParser():
    """Returns an argument parser."""
    parser = commandline.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mojo-root", required=True, help="Root of the mojo files."
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="Path for mojo generated code. "
        "Must be the same as the mojo bindings output dir.",
    )
    parser.add_argument(
        "--mojom-file-list", help="Mojom filenames passed as a file."
    )
    parser.add_argument(
        "--mojoms", default=[], nargs="+", help="Mojom filenames."
    )
    parser.add_argument(
        "--generator-overrides",
        default=[],
        nargs="+",
        help="The json config of the generator overrides.",
    )
    return parser


def main(argv):
    parser = GetParser()
    opts = parser.parse_args(argv)
    if opts.mojom_file_list:
        opts.mojoms.extend(
            Path(opts.mojom_file_list).read_text(encoding="utf-8").split()
        )

    opts.Freeze()

    if not opts.mojoms:
        raise parser.error(
            "Must list at least one mojom file via --mojoms or "
            "--mojom-file-list"
        )

    Generate(
        opts.mojoms, opts.mojo_root, opts.output_dir, opts.generator_overrides
    )


if __name__ == "__main__":
    commandline.ScriptWrapperMain(lambda _: main)
