# -*- coding: utf-8 -*-
# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Library for generating ChromeOS ConfigFS private data file."""

from __future__ import print_function

import os
import subprocess
import tempfile


def Serialize(obj):
    """Convert a string, integer, bytes, or bool to its file representation.

    Args:
        obj: The string, integer, bytes, or bool to serialize.

    Returns:
        The bytes representation of the object suitable for dumping into a file.
    """
    if isinstance(obj, bytes):
        return obj
    if isinstance(obj, bool):
        return b"true" if obj else b"false"
    return str(obj).encode("utf-8")


def WriteConfigFSFiles(config, base_path):
    """Recursive function to write ConfigFS data out to files and directories.

    Args:
        config: The configuration item (dict, list, str, int, or bool).
        base_path: The path to write out to.
    """
    if isinstance(config, dict):
        iterator = config.items()
    elif isinstance(config, list):
        iterator = enumerate(config)
    else:
        iterator = None

    if iterator is not None:
        os.makedirs(base_path, mode=0o755)
        for name, entry in iterator:
            path = os.path.join(base_path, str(name))
            WriteConfigFSFiles(entry, path)
    else:
        with open(
            os.open(base_path, os.O_CREAT | os.O_WRONLY, 0o644), "wb"
        ) as f:
            f.write(Serialize(config))


def GenerateConfigFSData(config, output_fs):
    """Generate the ConfigFS private data.

    Args:
        config: The configuration dictionary.
        output_fs: The file name to write the SquashFS image at.
    """
    with tempfile.TemporaryDirectory(prefix="configfs.") as configdir:
        os.chmod(configdir, 0o755)
        WriteConfigFSFiles(config, os.path.join(configdir, "v1"))
        subprocess.run(
            [
                "mksquashfs",
                configdir,
                output_fs,
                "-no-xattrs",
                "-noappend",
                "-all-root",
            ],
            check=True,
            stdout=subprocess.PIPE,
        )
