# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""The setuptools setup file."""

from setuptools import find_packages
from setuptools import setup


setup(
    name="cros_camera_app",
    version="0.1",
    description="Command line tool for CCA (ChromeOS Camera App)",
    author="Shik Chen",
    author_email="shik@chromium.org",
    license="BSD-Google",
    packages=find_packages(),
    package_data={"cros_camera_app": ["extension.js"]},
    include_package_data=True,
    install_requires=["ws4py"],
    entry_points={
        "console_scripts": [
            "cros_camera_app = cros_camera_app.cli.main:main",
            "cca = cros_camera_app.cli.main:main",
        ]
    },
)
