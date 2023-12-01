# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Pytest configuration."""

import os
import pathlib
import subprocess

import pytest


def pytest_addoption(parser):
    here = pathlib.Path(__file__).parent
    parser.addoption(
        "--executable",
        type=pathlib.Path,
        default=(here / ".." / "build" / "crosid.test").resolve(),
    )
    parser.addoption(
        "--llvm-coverage-out",
        type=pathlib.Path,
    )


@pytest.fixture(scope="session")
def executable_path(request):
    return request.config.option.executable


@pytest.fixture(scope="session")
def coverage_dir(request, tmp_path_factory):
    coverage_out = request.config.option.llvm_coverage_out
    if coverage_out:
        coverage_tmp_dir = tmp_path_factory.mktemp("coverage")
        yield coverage_tmp_dir

        # Merge coverage after tests finish
        subprocess.run(
            [
                "llvm-profdata",
                "merge",
                *coverage_tmp_dir.iterdir(),
                "-o",
                coverage_out,
            ],
            check=True,
        )
    else:
        yield


# pylint: disable=redefined-outer-name
@pytest.fixture(autouse=True)
def llvm_coverage(coverage_dir):
    if coverage_dir:
        coverage_raw = coverage_dir / "coverage-%p.profraw"
        os.environ["LLVM_PROFILE_FILE"] = str(coverage_raw)
