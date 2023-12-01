#!/usr/bin/env python3
# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""Builds the Rust toolchain used to compile and run TockOS."""

import argparse
import logging
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Iterable, List, NamedTuple, Optional

# The target triples that we want this toolchain to be able to build binaries
# for. ATM this consists of the host and one target. If you update this,
# remember to update |write_config_toml| with info about the compilers to use.
#
# _A_ rust compiler is needed for the host because some packages have build
# scripts (e.g., build.rs), and Ti50 has previously expressed interest in
# running _some_ tests in a test environment that runs natively on the host.
# It's unclear how difficult it'd be to use the CrOS Rust toolchain for both of
# these, given that said toolchain is locked to the stable channel, and is
# likely to be a very different version of Rust than Ti50's toolchain.
TARGET_TRIPLES_TO_SHIP = (
    'x86_64-unknown-linux-gnu',
    'riscv32imc-unknown-none-elf',
)


class RustComponent(NamedTuple):
  """A component of Rust that we want to build and install."""
  # The name of the component that |./x.py dist| understands.
  dist_build_name: str
  # A regex pattern that matches the tarball produced for this component under
  # dist/.
  dist_tarball_pattern: str
  # Whether the component's dist tarballs are per-triple.
  dist_tarballs_are_per_triple: bool


# Components we ship as a part of our toolchain.
COMPONENTS_TO_SHIP = (
    # cargo, which is shipped with |rustup| toolchains by default.
    RustComponent(
        dist_build_name='cargo',
        dist_tarball_pattern=r'^cargo-',
        dist_tarballs_are_per_triple=False,
    ),
    # clippy, which was requested by TockOS.
    RustComponent(
        dist_build_name='clippy',
        dist_tarball_pattern=r'^clippy-',
        dist_tarballs_are_per_triple=False,
    ),
    # llvm-tools-preview, which is apparently required by TockOS itself.
    RustComponent(
        dist_build_name='llvm-tools',
        dist_tarball_pattern=r'^llvm-tools-',
        dist_tarballs_are_per_triple=False,
    ),
    # src, which is required when cross-compiling in some contexts.
    RustComponent(
        dist_build_name='rust-src',
        dist_tarball_pattern=r'^rust-src-',
        dist_tarballs_are_per_triple=False,
    ),
    # src/librustc, which is the actual |rustc| compiler.
    RustComponent(
        dist_build_name='rustc',
        dist_tarball_pattern=r'^rustc-nightly-',
        dist_tarballs_are_per_triple=False,
    ),
    # rustfmt, the standard formatter for rust code.
    RustComponent(
        dist_build_name='rustfmt',
        dist_tarball_pattern=r'^rustfmt-',
        dist_tarballs_are_per_triple=False,
    ),
    # library/std, which consists of stdlib |rlib|s.
    RustComponent(
        dist_build_name='rust-std',
        dist_tarball_pattern=r'^rust-std-',
        dist_tarballs_are_per_triple=True,
    ),
)


def must_getenv(key: str) -> str:
  """Gets the value of an environment variable; raises if unset or empty."""
  x = os.getenv(key)
  if not x:
    raise ValueError(f'No value found for {key}; this env var is required')
  return x


def write_config_toml(rust_src: Path, rv_clang_bin: Path, install_prefix: Path,
                      rustc: Optional[Path], cargo: Optional[Path],
                      rustfmt: Optional[Path]) -> None:
  """Writes Rust's config.toml with the given parameters."""
  # We need a Pythony list, but formatted with double-quotes.
  assert not any('"' in x or '\\' in x
                 for x in TARGET_TRIPLES_TO_SHIP), TARGET_TRIPLES_TO_SHIP
  target_triples_str = ', '.join(f'"{x}"' for x in TARGET_TRIPLES_TO_SHIP)

  component_locations = (
      ('rustc', rustc),
      ('cargo', cargo),
      ('rustfmt', rustfmt),
  )
  optional_bootstrap_configuration = '\n'.join(
      f'{key} = "{exe}"' for key, exe in component_locations if exe is not None)

  cbuild = must_getenv('CBUILD')
  toml_contents = f"""
[build]
target = [{target_triples_str}]
extended = true
vendor = true
docs = false
python = "{must_getenv('EPYTHON')}"
submodules = false
profiler = true
optimized-compiler-builtins = true
{optional_bootstrap_configuration}

[llvm]
ccache = true
use-libcxx = true
ninja = true
# Fix for "error: could not find native static library `c++`"
static-libstdcpp = false
# Build only what we use
targets = "X86;RISCV"

[install]
prefix = "{install_prefix}"

[rust]
# Provide llvm-tools like llvm-objcopy for the llvm-tools package.
llvm-tools = true
codegen-units = 0
codegen-tests = false
# Build with nightly features
channel = "nightly"
# https://rust-lang.github.io/rfcs/2603-rust-symbol-name-mangling-v0.html
new-symbol-mangling = true
lld = true
default-linker = "{cbuild}-clang++"

[target.riscv32imc-unknown-none-elf]
cc = "{rv_clang_bin}/clang"
cxx = "{rv_clang_bin}/clang++"
linker = "{rv_clang_bin}/clang++"

[target.x86_64-unknown-linux-gnu]
cc = "x86_64-pc-linux-gnu-clang"
cxx = "x86_64-pc-linux-gnu-clang++"
linker = "x86_64-pc-linux-gnu-clang++"
"""

  (rust_src / 'config.toml').write_text(toml_contents, encoding='utf-8')

  # Create .cargo/config.toml to configure vendored sources
  cargo_toml_contents = f"""
[source]
[source.crates-io]
replace-with = "vendored-sources"

[source.vendored-sources]
directory = "vendor"

[target.x86_64-unknown-linux-gnu]
linker = "{cbuild}-clang++"
rustflags = ["-L", "/usr/x86_64-cros-linux-gnu/usr/lib64"]

[target.{cbuild}]
rustflags = ["-L", "/usr/x86_64-cros-linux-gnu/usr/lib64"]
linker = "{cbuild}-clang++"
"""
  cargo_config = rust_src / '.cargo'
  cargo_config.mkdir(exist_ok=True)
  (cargo_config / 'config.toml').write_text(cargo_toml_contents, encoding='utf-8')


def compile_rust_src(rust_src: Path) -> None:
  """Compiles all targets specified by COMPONENTS_TO_SHIP."""
  targets = [x.dist_build_name for x in COMPONENTS_TO_SHIP]
  subprocess.check_call(['./x.py', 'dist', '--verbose', '--color=never'] + targets, cwd=rust_src)


def copy_tree(input_path: Path, output_path: Path,
              ignore_file_names: Iterable[str]):
  """shutil.copytree with dirs_exist_ok=True.

  dirs_exist_ok=True is only available in py3.8+.
  """
  output_path.mkdir(parents=True, exist_ok=True)
  for root, _, files in os.walk(input_path):
    root = Path(root).relative_to(input_path)
    input_root = input_path / root
    output_root = output_path / root
    output_root.mkdir(exist_ok=True)
    for f in files:
      if f in ignore_file_names:
        continue

      output_file = output_root / f
      if output_file.exists():
        raise ValueError(f'File at {output_file} already exists; refusing to '
                         'overwrite')
      logging.debug('Copying %s => %s', input_root / f, output_root / f)
      shutil.copy2(input_root / f, output_root / f)


def package_rust_src(rust_src: Path, install_dir: Path):
  """Installs all components built in |rust_src| into |install_dir|."""
  dist_path = rust_src / 'build' / 'dist'
  all_tarballs = [x for x in dist_path.iterdir() if x.name.endswith('.tar.gz')]
  temp_dir = Path(tempfile.mkdtemp(prefix='build_rust_package'))
  logging.info(f'Packaging tarballs {all_tarballs}')

  def install_component(tarball: Path) -> None:
    logging.info('Untarring %s into %s', tarball, temp_dir)

    # All tarballs unpack to a single directory, which is the tarball without
    # the |.tar.${comp}| suffix.
    subprocess.check_call(['tar', 'xaf', str(tarball)], cwd=temp_dir)

    subdir_name = tarball.stem
    tar_suffix = '.tar'
    assert tarball.stem.endswith(tar_suffix), subdir_name
    subdir_name = subdir_name[:-len(tar_suffix)]
    base_dir = temp_dir / subdir_name

    # ...And this directory itself should contain a |components| file
    # describing what components this tarball has.
    components = [
        x.strip()
        for x in (base_dir /
                  'components').read_text(encoding='utf-8').splitlines()
    ]

    for component in components:
      input_path = base_dir / component
      logging.info('Installing component at %s into %s', input_path,
                   install_dir)
      copy_tree(
          input_path,
          install_dir,
          ignore_file_names=('manifest.in',),
      )

      # All inputs have a manifest.in at their root, which describes the files
      # installed by the given component. |rustup| likes to include those in
      # the final installation directory, and that seems like a generally okay
      # idea. These are copied _purely_ for informational purposes, rather than
      # serving some functional goal.
      manifest_dir = install_dir / 'lib' / 'rustlib'
      manifest_dir.mkdir(parents=True, exist_ok=True)
      manifest_name = f'manifest-{input_path.name}'
      shutil.copyfile(input_path / 'manifest.in', manifest_dir / manifest_name)

  try:
    install_dir.mkdir(parents=True, exist_ok=True)

    for component in COMPONENTS_TO_SHIP:
      logging.info(f'Installing component {component}')
      regex = re.compile(component.dist_tarball_pattern)
      targets = [x for x in all_tarballs if regex.search(x.name)]
      logging.info(f'Targets to ship: {targets}')
      if component.dist_tarballs_are_per_triple:
        for target_triple in TARGET_TRIPLES_TO_SHIP:
          ts = [x for x in targets if target_triple in x.name]
          if len(ts) != 1:
            raise ValueError(f'Expected exactly one match for {component} with '
                             f'triple {target_triple}; got {ts}')
          install_component(ts[0])
      else:
        if len(targets) != 1:
          raise ValueError(f'Expected exactly one match for {component}; '
                           f'got {targets} all tarballs {all_tarballs}')
        install_component(targets[0])
  except:
    logging.error('Packaging failed; leaving tempdir around at %s', temp_dir)
    raise
  else:
    logging.info('Packaging succeeded; cleaning up tempdir. Results are in %s',
                 install_dir)
    shutil.rmtree(temp_dir)


def get_parser():
  """Creates a parser for commandline args."""
  parser = argparse.ArgumentParser(
      description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
  parser.add_argument(
      '--rust-src',
      required=True,
      type=Path,
      help="Path to rust's source code",
  )
  parser.add_argument(
      '--install-dir',
      required=True,
      type=Path,
      help='Path to the directory in which we should put installation '
      'artifacts',
  )
  parser.add_argument(
      '--install-prefix',
      required=True,
      type=Path,
      help='Prefix under which installed artifacts will sit on the system',
  )
  parser.add_argument(
      '--rv-clang-bin',
      required=True,
      type=Path,
      help='Path the bin/ directory of a riscv-enabled clang',
  )
  parser.add_argument(
      '--rustc',
      type=Path,
      help='Optional path to the rustc we should use to bootstrap the '
      'compiler',
  )
  parser.add_argument(
      '--cargo',
      type=Path,
      help='Optional path to the cargo we should use to bootstrap the '
      'compiler',
  )
  parser.add_argument(
      '--rustfmt',
      type=Path,
      help='Optional path to the rustfmt we should use to bootstrap the '
      'compiler',
  )
  return parser


def main(argv: List[str]):
  logging.basicConfig(
      format='%(asctime)s: %(levelname)s: %(filename)s:%(lineno)d: %(message)s',
      level=logging.INFO,
  )

  parser = get_parser()
  opts = parser.parse_args(argv)

  install_dir = opts.install_dir.resolve()
  rust_src = opts.rust_src.resolve()
  rv_clang_bin = opts.rv_clang_bin.resolve()
  # This might not exist yet, so we don't want to resolve() it.
  install_prefix = opts.install_prefix
  if not install_prefix.is_absolute():
    parser.error('--install_prefix should be an absolute path')

  cargo = Path(opts.cargo).resolve() if opts.cargo else None
  rustc = Path(opts.rustc).resolve() if opts.rustc else None
  rustfmt = Path(opts.rustfmt).resolve() if opts.rustfmt else None

  write_config_toml(rust_src, rv_clang_bin, install_prefix, rustc, cargo,
                    rustfmt)
  compile_rust_src(rust_src)
  package_rust_src(rust_src, install_dir)


if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))
