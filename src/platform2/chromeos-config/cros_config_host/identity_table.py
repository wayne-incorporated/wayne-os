# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Functions for generating the identity table (identity.bin)."""

import enum
import struct


STRUCT_VERSION = 4
# version, entry_count
HEADER_FORMAT = "<LL"
# flags, frid match,
# sku match, custom label match, firmware manifest name
ENTRY_FORMAT = "<LLLLL"


class EntryFlags(enum.Enum):
    """The flags used at the beginning of each entry."""

    HAS_SKU_ID = 1 << 0
    HAS_CUSTOM_LABEL_TAG = 1 << 1

    # This device uses a customization ID from VPD to match instead of a
    # whitelabel tag. This is deprecated for new devices since 2017, so
    # it should only be set for old pre-unibuild migrations.
    HAS_CUSTOMIZATION_ID = 1 << 2

    # Config should match based on FRID.
    HAS_FRID = 1 << 3


def WriteIdentityStruct(config, output_file):
    """Write out the data file needed to provide system identification.

    This data file is used at runtime by cros_configfs to probe the
    identity of the device.  The struct must align with the C code in
    cros_configfs.

    Args:
        config: The configuration dictionary (containing "chromeos").
        output_file: A file-like object to write to, opened in binary mode.
    """
    device_configs = config["chromeos"]["configs"]
    string_table = []

    # Add a string to the table if it does to exist. Return the number
    # of bytes offset the string will live from the base of the string
    # table.
    def _StringTableIndex(string):
        if string is None:
            return 0

        string = string.lower()
        string = string.encode("utf-8") + b"\000"
        if string not in string_table:
            string_table.append(string)

        index = 0
        for entry in string_table:
            if entry == string:
                return index
            index += len(entry)

    # Write the header of the struct.
    output_file.write(
        struct.pack(HEADER_FORMAT, STRUCT_VERSION, len(device_configs))
    )

    # Write each of the entry structs.
    for device_config in device_configs:
        identity_info = device_config.get("identity", {})
        firmware_manifest_key = device_config.get("firmware", {}).get(
            "image-name", device_config["name"]
        )
        flags = 0
        sku_id = 0
        if "sku-id" in identity_info:
            flags |= EntryFlags.HAS_SKU_ID.value
            sku_id = identity_info["sku-id"]

        frid_match = None
        custom_label_match = None
        if "frid" in identity_info:
            flags |= EntryFlags.HAS_FRID.value
            frid_match = identity_info["frid"]

        if "customization-id" in identity_info:
            flags |= EntryFlags.HAS_CUSTOMIZATION_ID.value
            custom_label_match = identity_info["customization-id"]
        elif "custom-label-tag" in identity_info:
            flags |= EntryFlags.HAS_CUSTOM_LABEL_TAG.value
            custom_label_match = identity_info["custom-label-tag"]

        output_file.write(
            struct.pack(
                ENTRY_FORMAT,
                flags,
                _StringTableIndex(frid_match),
                sku_id,
                _StringTableIndex(custom_label_match),
                _StringTableIndex(firmware_manifest_key),
            )
        )

    for entry in string_table:
        output_file.write(entry)
