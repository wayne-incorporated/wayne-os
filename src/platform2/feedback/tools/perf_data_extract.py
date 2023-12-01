#!/usr/bin/env python3
# Copyright 2019 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# pylint: disable=import-error

"""Extracts `perf-data` and `perfetto-data` from a feedback logs archive.

Example:
  perf_data_extract.py system_logs.zip /tmp
"""

import argparse
import base64
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from typing import List, Optional
import zipfile


def get_perf_data(zip_file):
    """Extract the blobs of perf-data/perfetto-data from a zip archive.

    Args:
      zip_file: (str) file path to system logs archive.

    Returns:
      (str: perf-data, str: perfetto-data)
    """
    perf_prefix = "perf-data="
    perf_data = None
    perfetto_prefix = "perfetto-data="
    perfetto_data = None

    # Some blobs contain extra junk in the form "<TAG: NN>" (e.g., "<UID: 2>")
    # which we need to filter out.
    # TODO(skyostil): Figure out what is causing this corruption.
    junk_tag = re.compile(r"<[A-Z0-9: ]*>")
    blob_start = "<base64>:"

    def read_next_blob(log, line):
        while line:
            if blob_start in line:
                blob = line[line.index(blob_start) + len(blob_start) :].strip()
                blob = re.sub(junk_tag, "", blob)
                # These blobs are often truncated, so trim them down further
                # down to the closest valid base64-encoded length.
                if len(blob) * 3 % 4:
                    blob = blob[: -(len(blob) * 3 % 4)] + "=="
                return base64.b64decode(blob)
            line = log.readline()

    with tempfile.TemporaryDirectory() as tmp_dir:
        with zipfile.ZipFile(zip_file) as z:
            z.extractall(path=tmp_dir)
        log_path = os.path.join(tmp_dir, "system_logs.txt")
        with open(log_path, encoding="utf-8") as log:
            while line := log.readline():
                if line.startswith(perf_prefix):
                    perf_data = read_next_blob(log, line)
                elif line.startswith(perfetto_prefix):
                    perfetto_data = read_next_blob(log, line)
            return (perf_data, perfetto_data)


def parse_args(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "system_logs_zip", type=Path, help="System logs zip file."
    )
    parser.add_argument(
        "out",
        type=Path,
        default=os.curdir,
        help="Output path (defaults to current dir).",
    )
    return parser.parse_args(argv)


# The two decompression functions below can decompress a possibly truncated
# compressed bitstream. If truncation is detected, the decompressor will print a
# warning to stderr and return the data recovered so far.
# TODO(skyostil): Find out where and why this data is getting truncated.
def decompress_lzma(lzma_data):
    """Best-effort decompresses potentially truncated lzma data."""
    ret = subprocess.run(
        ["xz", "-dc", "-"], input=lzma_data, check=False, stdout=subprocess.PIPE
    )
    return ret.stdout


def decompress_zstd(zstd_data):
    """Best-effort decompresses potentially truncated zstd data."""
    ret = subprocess.run(
        ["zstd", "-dc", "-"],
        input=zstd_data,
        check=False,
        stdout=subprocess.PIPE,
    )
    return ret.stdout


def main(argv: Optional[List[str]] = None) -> Optional[int]:
    opts = parse_args(argv)
    perf_data, perfetto_data = get_perf_data(opts.system_logs_zip)

    if not perf_data and not perfetto_data:
        sys.exit("Error: perf-data/perfetto-data not found in the system logs")

    if perf_data:
        out = os.path.join(opts.out, "feedback_perf.data")
        print("Writing perf data to", out)
        perf_data = decompress_lzma(perf_data)
        with open(out, "wb") as f:
            f.write(perf_data)

    if perfetto_data:
        out = os.path.join(opts.out, "feedback.perfetto-trace")
        print("Writing perfetto data to", out)
        perfetto_data = decompress_zstd(perfetto_data)
        with open(out, "wb") as f:
            f.write(perfetto_data)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
