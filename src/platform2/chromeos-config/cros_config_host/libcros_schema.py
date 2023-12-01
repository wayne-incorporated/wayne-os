# -*- coding: utf-8 -*-
# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Chrome OS Configuration Schema library.

Provides common cros_config and cros_config_test schema functions.
"""

from __future__ import print_function

import collections
import json
import os
import re

from jsonschema import validate  # pylint: disable=import-error
import yaml  # pylint: disable=import-error


def FormatJson(config):
    """Formats JSON for output or printing.

    Args:
        config: Dictionary to be output
    """
    return json.dumps(config, sort_keys=True, indent=2, separators=(",", ": "))


def LoadYaml(stream):
    """Load the first YAML document in a stream.

    Args:
        stream: A file-like object or string which contains a YAML
        document.

    Returns:
        A Python object which corresponds to the YAML source.
    """

    # Prefer libyaml, as it's significantly faster than the default
    # Python loader, but fallback to the Python loader when unavailable.
    # While libyaml is available in the chroot, this supports execution
    # in non-chroot environments like LUCI builders.
    if yaml.__with_libyaml__:
        loader = yaml.CSafeLoader
    else:
        loader = yaml.SafeLoader

    return yaml.load(stream, Loader=loader)


def ValidateConfigSchema(schema, config):
    """Validates a transformed config against the schema specified.

    Verifies that the config complies with the schema supplied.

    Args:
        schema: Source schema used to verify the config.
        config: Config (transformed) that will be verified.
    """
    json_config = json.loads(config)
    schema_json = LoadYaml(schema)
    validate(json_config, schema_json)


def FindImports(config_file, includes):
    """Recursively looks up and finds files to include for yaml.

    Args:
        config_file: Path to the config file for which to apply imports.
        includes: List that is built up through processing the files.
    """
    working_dir = os.path.dirname(config_file)
    with open(config_file, "r", encoding="utf-8") as config_stream:
        config_lines = config_stream.readlines()
        yaml_import_lines = []
        found_imports = False
        # Parsing out just the imports snippet is required because the YAML
        # isn't valid until the imports are eval'd.
        for line in config_lines:
            if re.match(r"^imports", line):
                found_imports = True
                yaml_import_lines.append(line)
            elif found_imports:
                match = re.match(r" *- (.*)", line)
                if match:
                    yaml_import_lines.append(line)
                else:
                    break

        if yaml_import_lines:
            yaml_import = LoadYaml("\n".join(yaml_import_lines))

            for import_file in yaml_import.get("imports", []):
                full_path = os.path.join(working_dir, import_file)
                FindImports(full_path, includes)
        includes.append(config_file)


def ApplyImports(config_file):
    """Parses the imports statements and applies them to a result config.

    Args:
        config_file: Path to the config file for which to apply imports.

    Returns:
        Raw config with the imports applied.
    """
    import_files = []
    FindImports(config_file, import_files)

    all_yaml_files = []
    for import_file in import_files:
        with open(import_file, "r", encoding="utf-8") as yaml_stream:
            all_yaml_files.append(yaml_stream.read())

    return "\n".join(all_yaml_files)


# Attributes that are defined as a function of the schema.
#   build_only_element: Property is only used during build time.
#   default_value: Default value if no property is present.
PropertyAttrs = collections.namedtuple(
    "PropertyAttrs", ["build_only_element", "default_value"]
)


def GetSchemaPropertyAttrs(schema_yaml):
    """Returns schema defined attributes on a per property basis.

    Args:
        schema_yaml: Source schema that contains the properties.

    Returns:
        Dictionary
            key - full path to the property in the schema
            value - PropertyAttrs object with the schema attributes
    """
    root_path = "properties/chromeos/properties/configs/items/properties"
    schema_node = schema_yaml
    for element in root_path.split("/"):
        schema_node = schema_node[element]

    result = collections.OrderedDict()
    _GetSchemaPropertyAttrs(schema_node, [], result)
    return result


def _GetSchemaPropertyAttrs(schema_node, path, result):
    """Recursively extracts property attributes from the schema.

    Args:
        schema_node: Single node from the schema
        path: Running path that a given node maps to
        result: Running collection of results
    """
    for key in schema_node:
        new_path = path + [key]
        current_node = schema_node[key]
        if not isinstance(current_node, dict):
            # Skip over additionalProperties, required fields.
            continue

        node_type = current_node["type"]

        build_only = current_node.get("build-only-element", False)
        default_value = current_node.get("default", None)
        if build_only or default_value:
            result["/%s" % "/".join(new_path)] = PropertyAttrs(
                build_only, default_value
            )

        if node_type == "array":
            if "properties" in current_node["items"]:
                _GetSchemaPropertyAttrs(
                    current_node["items"]["properties"], new_path, result
                )
        elif node_type == "object":
            if "oneOf" in current_node:
                for element in current_node["oneOf"]:
                    _GetSchemaPropertyAttrs(
                        element["properties"], new_path, result
                    )
            elif "properties" in current_node:
                _GetSchemaPropertyAttrs(
                    current_node["properties"], new_path, result
                )
