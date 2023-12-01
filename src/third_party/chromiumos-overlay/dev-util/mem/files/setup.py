#!/usr/bin/env python3

# Copyright 2014 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

from setuptools import setup

setup(
  name='mem',
  version='0.0.1',
  description='Tools for accessing /dev/mem',
  py_modules=['mem'],
  entry_points={
    'console_scripts': [
      'mem = mem:main',
    ]
  }
)
