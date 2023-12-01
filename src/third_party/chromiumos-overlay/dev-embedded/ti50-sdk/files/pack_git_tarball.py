#!/usr/bin/env python3
# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Packs a tarball from a git source tree."""

import argparse
import errno
import logging
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import List, Iterable


def enumerate_untracked_files(in_dir: Path) -> List[Path]:
  """Returns a list of files untracked by git in |in_dir|."""
  return subprocess.check_output(
      ['git', 'ls-files', '--others'],
      encoding='utf-8',
      cwd=in_dir,
  ).strip().splitlines()


def get_git_sha(in_dir: Path) -> str:
  """Returns the git SHA representing HEAD in |in_dir|."""
  return subprocess.check_output(
      ['git', 'rev-parse', 'HEAD'],
      encoding='utf-8',
      cwd=in_dir,
  ).strip()


def copy_git_tree_ignoring(from_path: Path, to_dir: Path,
                           ignore: Iterable[str]):
  """Copies |from_path| into |to_dir|, ignoring all subdirs in |ignore|.

  All paths in |ignore| should be relative to |from_dir|.

  This also removes all .git directories and other .git* files.
  """
  # shutil.copytree is incredibly slow (it took many minutes to copy my Rust
  # tree from SSD -> memfs; |rsync| took 20secs). Prefer to use something
  # faster, then go clean up afterward. This is theoretically problematic in
  # some cases, but for the specific task of "copy some sources from this git
  # directory into a tarball," seems to work fine.

  # If we just hand rsync the directory, it'll copy it into
  # |to_dir / from_path.name|; we want the contents to go into |to_dir|
  # directly.
  to_dir.mkdir(parents=True)

  rsync_command = [
      'rsync',
      '-a',
      '--exclude=.git*',
  ]
  rsync_command += (str(x) for x in from_path.iterdir() if x.name != '.git')
  rsync_command.append(str(to_dir))
  subprocess.check_call(rsync_command)

  for x in (to_dir / x for x in ignore):
    # x.exists() will read through the symlink; we therefore need to treat
    # symlinks specially.
    if not x.is_symlink() and not x.exists():
      continue

    if not x.is_symlink() and x.is_dir():
      shutil.rmtree(x)
    else:
      os.unlink(x)

  # Now, since this is all meant to be version controlled by git, empty
  # directories shouldn't exist. Clean those.
  for root_dir, _, _ in os.walk(to_dir, topdown=False):
    try:
      os.rmdir(root_dir)
    except OSError as e:
      if e.errno != errno.ENOTEMPTY:
        raise
    else:
      logging.debug('Removing empty directory %s', root_dir)


def get_parser():
  """Creates a parser for commandline args."""
  parser = argparse.ArgumentParser(
      description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
  parser.add_argument('--debug', action='store_true')
  parser.add_argument(
      '--git-dir',
      required=True,
      type=Path,
      help="Path to the root of your git directory. If applicable, don't "
      'forget to sync submodules!')
  parser.add_argument(
      '--output-prefix',
      required=True,
      type=Path,
      help='Prefix at which to where to place the tarball. This has a few '
      'components. For example, given a prefix of |/foo/bar/baz/rust| and '
      "packing a repo at SHA abcdef1234567890, the output tarball's name will "
      'be /foo/bar/baz/rust-abcdef1234-src.tar.xz, which will contain a '
      'single directory, rust-abcdef1234-src/, which contains the desired '
      'bits of |--git-dir|.')
  parser.add_argument(
      '--post-copy-command',
      help='Command to run after copying sources to a tempdir, in the root '
      'of said tempdir. Passed directly to `bash -c`.')
  return parser


def main(argv: List[str]):
  parser = get_parser()
  opts = parser.parse_args(argv)

  logging.basicConfig(level=logging.DEBUG if opts.debug else logging.INFO)

  full_output_prefix = opts.output_prefix
  output_dir = full_output_prefix.parent.resolve()
  output_prefix = full_output_prefix.name

  post_copy_command = opts.post_copy_command
  git_dir = opts.git_dir.resolve()
  head_sha = get_git_sha(git_dir)

  # 12 is arbitrary, but should be enough for anyone(tm).
  sha_shorthand = head_sha[:12]

  output_file_name_no_ext = f'{output_prefix}-{sha_shorthand}-src'
  output_file = output_dir / f'{output_file_name_no_ext}.tar.xz'
  logging.info('Will pack %s at SHA %s into %s', git_dir, head_sha, output_file)

  logging.info('Enumerating untracked files...')
  untracked_files = enumerate_untracked_files(git_dir)

  with tempfile.TemporaryDirectory(prefix='pack_git_tarball_') as temp_dir:
    tar_dir = Path(temp_dir) / output_file_name_no_ext

    logging.info('Copying git tree to %s...', tar_dir)
    copy_git_tree_ignoring(
        git_dir,
        tar_dir,
        ignore=untracked_files,
    )

    # Stash the SHA for HEAD here, so it's easier for people to figure out
    # where the sources came from.
    sha_file = tar_dir / 'packed_git_sha'
    if sha_file.exists():
      raise RuntimeError(f"SHA file at {sha_file} already exists; it shouldn't")
    sha_file.write_text(head_sha, encoding='utf-8')

    if post_copy_command:
      logging.info('Running %r', post_copy_command)
      # Since we say bash in the `help` string, require the use of bash here
      # instead of using shell=True.
      subprocess.check_call(['bash', '-c', post_copy_command], cwd=tar_dir)

    logging.info('Tarring and compressing result')
    tar_file = f'{tar_dir}.tar'
    subprocess.check_call(
        [
            'tar',
            'cf',
            tar_file,
            output_file_name_no_ext,
        ],
        cwd=temp_dir,
    )

    subprocess.check_call(['xz', '-T0', '-9', tar_file])
    shutil.move(f'{tar_file}.xz', output_file)

  logging.info('Result is available at %s', output_file)


if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))
