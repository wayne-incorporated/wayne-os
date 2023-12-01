# -*- coding: utf-8 -*-
# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Chrome OS Configuration access library.

Provides build-time access to the model configuration on the host. It is used
for reading from the model configuration. Consider using cros_config_host.py
for CLI access to this library.
"""

from __future__ import print_function

import os
import sys


# pylint: disable=wrong-import-position
this_dir = os.path.dirname(__file__)
sys.path.insert(0, this_dir)
import libcros_config_host_json  # pylint: disable=import-error


sys.path.pop(0)


UNIBOARD_CONFIG_INSTALL_DIR = "usr/share/chromeos-config"


def CrosConfig(fname=None, model_filter_regex=None):
    """Create a new CrosConfigBaseImpl object

    This is in a separate function to allow us to (in the future) support YAML,
    which will have a different means of creating the impl class.

    Args:
        fname: Filename of config file
        model_filter_regex: Only returns configs that match the filter
    """
    if not fname:
        if "SYSROOT" not in os.environ:
            raise ValueError(
                "No model configuration is available outside the "
                "ebuild environemnt. You must specify one"
            )
        fname = os.path.join(
            os.environ["SYSROOT"],
            UNIBOARD_CONFIG_INSTALL_DIR,
            "yaml",
            "config.yaml",
        )
    with sys.stdin if fname == "-" else open(fname, encoding="utf-8") as infile:
        return libcros_config_host_json.CrosConfigJson(
            infile, model_filter_regex=model_filter_regex
        )
