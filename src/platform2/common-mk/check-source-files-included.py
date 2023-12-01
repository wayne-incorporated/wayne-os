#!/usr/bin/env python3
# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Ensure source files are not missed and included in a gn file.

Occasionally, a source file, especially a unit test file, is added to the repo
but is not included in the build. This kind of mistake can often evade code
review, or is discovered only later in the review stage and wasted time for
early discovery of errors. This script examines each source file and checks
whether they are present in a *.gn file in their project directory.
"""

import argparse
from pathlib import Path
from pathlib import PurePath
import sys
from typing import FrozenSet, Iterable, List, Optional, Tuple


TOP_DIR = Path(__file__).resolve().parent.parent

# Find chromite.
sys.path.insert(0, str(TOP_DIR.parent.parent))

# pylint: disable=wrong-import-position
from chromite.lib import cros_build_lib
from chromite.lib import git
from chromite.lint.linters import gnlint


class ProjectLiterals:
    """Manages project literals."""

    def __init__(self, commit: str):
        # A map that saves project literals.
        self._literals: map = {}
        self._commit: str = commit

    def GetLiterals(self, project: str) -> FrozenSet[PurePath]:
        """Get the literal source files from a project.

        If the literals have not gathered yet, gather them.

        Args:
            project: The project to get literals from.

        Returns:
            Literals from the specified project.
        """
        if project not in self._literals:
            self._literals[project] = self._GatherLiteralsFromProject(project)

        return self._literals[project]

    def _GatherLiteralsFromProject(self, project: str) -> FrozenSet[PurePath]:
        """Gather the literal source files from a project.

        Args:
            project: The project to gather source file literals from.

        Returns:
            A set of all source file literals from a project.
        """

        def _gather() -> Iterable[Tuple[PurePath, PurePath]]:
            """Generate the gn file path and its source file literals."""
            for gn_file in self._FindGnFiles(project):
                yield from (
                    (gn_file, literal)
                    for literal in ProjectLiterals._GatherLiteralsFromGn(
                        (TOP_DIR / project / gn_file).read_text(
                            encoding="utf-8"
                        )
                    )
                )

        def _resolve(gn_file: PurePath, literal: PurePath) -> PurePath:
            """Resolve a source file literal relative to the top dir."""
            return (
                (
                    TOP_DIR
                    / project
                    / PurePath(gn_file).parent
                    / gnlint.GetNodeValue(literal)
                )
                .resolve()
                .relative_to(TOP_DIR)
            )

        return frozenset(
            _resolve(gn_file, literal) for gn_file, literal in _gather()
        )

    def _FindGnFiles(self, project: str) -> Iterable[str]:
        """Find all gn files in a project.

        Args:
            project: The project to find gn files in.

        Returns:
            An iterable of all gn files.
        """
        # Any failure of RunGit will throw an uncaught exception and is
        # considered a failure of the script.
        result = git.RunGit(
            TOP_DIR / project,
            ["ls-tree", "--name-only", "-r", "-z", self._commit],
        )
        yield from (
            line for line in result.stdout.split("\0") if line.endswith(".gn")
        )

    @staticmethod
    def _GatherLiteralsFromGn(gn_data: str) -> List[dict]:
        """Gather all source file literals from a gn file.

        Args:
            gn_data: The content of a gn file to gather literals from.

        Returns:
            A list of literal assignments.
        """
        try:
            ast = gnlint.ParseAst(gn_data)
        except cros_build_lib.RunCommandError as e:
            cros_build_lib.Die("Failed to run gn format: %s", e)
        except Exception as e:
            cros_build_lib.Die("Invalid format: %s", e)

        return gnlint.FindAllLiteralAssignments(
            ast, ["sources"], operators=["=", "+="]
        )


def CheckSourceFileIncludedInBuild(commit: str, file_paths: List[str]) -> bool:
    """Check that source files are included in builds.

    Args:
        commit: The commit to check in.
        file_paths: Files modified in this commit.

    Returns:
        True if source files are included in a *.gn file in the project
        directory. False otherwise.
    """

    ret = True
    project_literals = ProjectLiterals(commit)

    for path in file_paths:
        if not path.endswith((".c", ".cc", ".cpp", ".cxx")):
            # Header files are not checked here because they do not necessarily
            # need to be present in a build file.
            continue

        path = PurePath(path)
        project = path.parts[0]
        if not (Path(project) / "BUILD.gn").exists():
            # This project does not use gn.
            # We are trying to be conservative here, as we don't want to check
            # projects that only uses gn in a subdirectory.
            continue
        if path not in project_literals.GetLiterals(project):
            print(
                f"{__file__}: {path} is not included in any "
                f"*.gn files in {project}. "
                "If you believe you have added the file via an intermediate "
                "variable, please ensure the source is set via source_set().",
                file=sys.stderr,
            )
            ret = False

    return ret


def get_parser():
    """Return an argument parser."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", help="Hash of commit to check in.")
    parser.add_argument("files", nargs="*", help="Files to check.")
    return parser


def main(argv: Optional[List[str]] = None) -> Optional[int]:
    parser = get_parser()
    opts = parser.parse_args(argv)
    # TODO(b/280853454): Extend the check to ensure that, when a build file is
    # changed, no source file (especially test file) is left unbuilt.
    #
    # This feature can be implemented as follows:
    # 1. If a BUILD.gn file is fed to the script, use git ls-tree to gather all
    #    source files in that project,
    # 2. Calling CheckSourceFileIncludedInBuild with all source files in that
    #    project as parameter to examine if all source files are included.
    return 0 if CheckSourceFileIncludedInBuild(opts.commit, opts.files) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
