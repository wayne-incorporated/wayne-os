#!/usr/bin/env python3
# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""Ebuild function generator to migrate src_install into GN.

Default values follow the default values of ebuild (see manpage of ebuild).
https://dev.gentoo.org/~zmedico/portage/doc/man/ebuild.5.html
"""

import os


VALID_INSTALL_TYPES = ("bin", "ins", "lib.a", "lib.so", "sbin", "exe")


class EbuildFunctionError(Exception):
    """The base exception for ebuild_function."""


class InvalidInstallTypeError(EbuildFunctionError):
    """Invalid type exception that is raised when install type is invalid."""

    def __init__(self):
        message = f'install_type must be {", ".join(VALID_INSTALL_TYPES)}'
        super().__init__(message)


def generate(
    sources,
    install_path=None,
    outputs=None,
    symlinks=None,
    recursive=False,
    options=None,
    command_type=None,
):
    """Generates commandlines for installing files using a ebuild function.

    Args:
        sources: A list of source files to be installed.
        install_path: A string of path to install into. When both install_path
          and symlinks are specified, it joins a install_path to symlinks.
          When command_type is "shared_library" or "static_library",
          install_path must end with "lib".
        outputs: A list of new file names to be installed as. If not specified,
          original file names are used.
        symlinks: A list of new symbolic links to be created. If specified,
          installation command becomes "dosym" and args except for sources
          are ignored.
        recursive: A boolean if you install them recursively. This is only
          available when command_type and symlinks are not specified.
        options: A string to be passed to xxopts. This is only available when
          command_type and symlinks are not specified.
        command_type: A string of where is the config defined.
          "executable", "shared_library", "static_library" and None are only
          allowed to be specified.
          The generated command depends on command_type.
            executable: dobin, dosbin, newbin, newsbin, doexe, newexe
            shared_library: dolib.so, newlib.so
            static_library: dolib.a, newlib.a
            None: doins, newins, dosym

    Returns:
        A list of commandlines correspond to given args.
        It can generate "doins", "dobin", "dosbin", "doexe", "dolib.a",
        "dolib.so", and "dosym". When "outputs" is specified, it generates
        new-command of those except for "dosym".
        doins:
        [
          ['insinto', 'path/to/install'],
          ['insopts', '-m0644'],
          ['doins', 'sources[0]', 'sources[1]', ...],
        ]
        dobin):
        [
          ['into', 'path/to/install'],
          ['dobin', 'sources[0]', 'sources[1]', ...],
        ]
        doexe):
        [
          ['exeinto', 'path/to/install'],
          ['doexe', 'sources[0]', 'sources[1]', ...],
        ]
        dosym:
        [
          ['dosym', 'sources[0]', 'path/to/symlink[0]'],
          ['dosym', 'sources[1]', 'path/to/symlink[1]'],
          ...
        ]
        dolib.a and dolib.so is the same as dobin.
        When "outputs" are specified, installation commands change to multiple
        commands of "newxxx" like dosym.
    """
    if not command_type:
        if not symlinks:
            install_type = "ins"
        else:
            install_type = "sym"
            if install_path:
                outputs = [
                    os.path.join(install_path, symlink) for symlink in symlinks
                ]
            else:
                outputs = symlinks

    elif command_type == "executable":
        assert install_path, (
            "install_path is required for" ' command_type="executable"'
        )
        # dobin and dosbin adds subdirectory "bin" and "sbin" respectively.
        # Therefore install path needs to be trimmed.
        new_install_path, install_type = os.path.split(install_path)
        if install_type not in ("bin", "sbin"):
            assert os.path.isabs(install_path), (
                "install_path must be absolute for executables"
                " other than */bin or */sbin."
            )
            install_type = "exe"
        else:
            install_path = new_install_path

    elif command_type == "shared_library":
        install_path, lib = os.path.split(install_path)
        assert (
            lib == "lib"
        ), "install_path must end in lib in a shared_library target"
        install_type = "lib.so"

    elif command_type == "static_library":
        install_path, lib = os.path.split(install_path)
        assert (
            lib == "lib"
        ), "install_path must end in lib in a static_library target"
        install_type = "lib.a"
    else:
        raise AssertionError(
            "unknown type. type must be executable,"
            " shared_library or static_library"
        )
    cmd_list = option_cmd(install_type, install_path, options)
    cmd_list += install(install_type, sources, outputs, recursive)
    return cmd_list


def sym_install(sources, symlinks):
    """Generates "dosym" commandlines.

    Args:
        sources: A list of source files of symbolic links.
        symlinks: A list of symbolic links to be created.

    Returns:
        A list of commandlines of "dosym".
        [
          ['dosym', 'sources[0]', 'symlinks[0]'],
          ['dosym', 'sources[1]', 'symlinks[1]'],
          ...
        ]
    """
    assert len(sources) == len(
        symlinks
    ), "the number of symlinks must be the same as sources"
    return [
        ["dosym", source, symlink] for source, symlink in zip(sources, symlinks)
    ]


def option_cmd(install_type, install_path="", options=None):
    """Generates commandlines of options appropriate for the |install_type|.

    Args:
        install_type: A string of a suffix of an installation command.
        install_path: A string of path to be installed into. This is passed to
          "xxxinto" commands.
        options: A string of options of installation. This is available only
          when install_type == "ins". This is passed to "xxxopts".

    Returns:
        A list of commandlines for specifying options.
        doins options (install_type == "ins"):
        [
          ['insinto', 'path/to/install'],
          ['insopts', '-m0644'],
        ]
        dobin, dosbin, dolib.so, dolib.a options:
        [
          ['into', 'path/to/install']
        ]
    """
    if install_type == "ins":
        return [
            ["insinto", install_path or "/"],
            ["insopts", options or "-m0644"],
        ]
    if install_type == "exe":
        assert install_path
        return [["exeinto", install_path]]
    if install_type in VALID_INSTALL_TYPES:
        return [["into", install_path or "/usr"]]
    return []


def install(install_type, sources, outputs=None, recursive=False):
    """Generates commandlines for installation.

    When |outputs| is specified, it generates new command.

    Args:
        install_type: A string of a suffix of an installation command.
        sources: A list of source files to be installed.
        outputs: A list of new file names to be installed as. If not specified,
          original file names are used.
        recursive: A boolean if you install them recursively. This is available
          only when install_type == "ins" and outputs are not specified.

    Returns:
        A list of commandlines for installation.
    """
    if install_type == "sym":
        return sym_install(sources, outputs)
    if not outputs:
        return do_command(install_type, sources, recursive)
    return new_command(install_type, sources, outputs)


def do_command(install_type, sources, recursive=False):
    """Generates commandlines of do-command.

    Args:
        install_type: A string of a suffix of an installation command.
          "ins", "bin", "sbin", "lib.so" and "lib.a" are allowed.
        sources: A list of source files to be installed.
        recursive: A boolean if you install them recursively. This is available
          only when install_type == "ins".

    Returns:
        A list of commandlines for installation.
        [
          ['dobin', 'sources[0]', 'sources[1]', ...]
        ]

        Especially, when install_type == "ins" and recursive == true:
        [
          ['doins', '-r', 'sources[0]', 'sources[1]', ...]
        ]
    """
    if install_type not in VALID_INSTALL_TYPES:
        raise InvalidInstallTypeError()
    recursive_opts = []
    if install_type == "ins" and recursive:
        recursive_opts = ["-r"]
    return [["do%s" % install_type] + recursive_opts + sources]


def new_command(install_type, sources, outputs):
    """Generates commandlines of new-command.

    Args:
        install_type: A string of a suffix of an installation command.
          "ins", "bin", "sbin", "lib.so" and "lib.a" are allowed.
        sources: A list of source files to be installed.
        outputs: A list of new file names to be installed as.

    Returns:
        A list of commandlines for installation.
        [
          ['newins', 'sources[0]', 'outputs[0]'],
          ['newins', 'sources[1]', 'outputs[1]'],
          ...
        ]
    """
    if install_type not in VALID_INSTALL_TYPES:
        raise InvalidInstallTypeError()
    assert len(sources) == len(
        outputs
    ), "the number of outputs must be the same as sources"
    return [
        ["new%s" % install_type, source, output]
        for source, output in zip(sources, outputs)
    ]
