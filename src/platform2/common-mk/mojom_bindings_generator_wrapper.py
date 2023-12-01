#!/usr/bin/env python3
# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Thin wrapper of Mojo's mojom_bindings_generator.py.

To generate C++ files from mojom, it is necessary to run
mojom_bindings_generator.py three times
 - without --generate_non_variant_code or --generate_non_variant_code
 - with --generate_non_variant_code only
 - with both --generate_non_variant_code and --generate_message_ids

However, gni's "rule" does not support multiple "action"s. So, instead,
use this simple python wrapper.

Usage:
  python mojom_bindings_generator_wrapper.py ${libbase_ver} \
    ${MOJOM_BINDINGS_GENERATOR} \
    [... and more args/flags to be passed to the mojom_bindings_generator.py]
"""

import subprocess
import sys


def main(argv):
    subprocess.check_call(argv[2:])
    subprocess.check_call(argv[2:] + ["--generate_non_variant_code"])
    subprocess.check_call(
        argv[2:] + ["--generate_non_variant_code", "--generate_message_ids"]
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv))
