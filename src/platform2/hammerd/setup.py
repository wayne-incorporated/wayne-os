# -*- coding: utf-8 -*-
# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""The setuptools setup file."""

from __future__ import print_function

from setuptools import setup


setup(
    name="hammerd_api",
    version="0.1",
    author="Chih-Yu Huang",
    author_email="akahuang@google.com",
    py_modules=["hammerd_api"],
    scripts=["hammerd_api_demo.py", "hammer_info.py"],
    description="The wrapper of hammerd API.",
)
