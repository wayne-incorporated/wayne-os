# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

project(
    'crosid', 'c',
    default_options: [
        'c_std=gnu11',
        'warning_level=3',
        'werror=true',
        'optimization=3',
    ],
)

# Require that externally-visible symbols have a prototype.  This
# helps find missing usages of 'static'.
add_global_arguments('-Wstrict-prototypes', language: 'c')
add_global_arguments('-Wundef', language: 'c')
add_global_arguments('-Wmissing-variable-declarations', language: 'c')
add_global_arguments('-Wmissing-prototypes', language: 'c')
common_c_args = ['-DCROSID_INTERNAL_API']

lib_files = [
    'api.c',
    'frid.c',
    'file_ops.c',
    'logging.c',
    'match.c',
    'probe.c',
    'sku.c',
]
src_files = lib_files + ['main.c']

libcrosid = library('crosid', lib_files, c_args: common_c_args, install: true)

# Generate crosid.pc
pkg = import('pkgconfig')
pkg.generate(
    libraries: libcrosid,
    version: '1.0',
    name: 'libcrosid',
    filebase: 'crosid',
    description: 'Chrome OS device identity library',
)

executable(
    'crosid',
    src_files,
    c_args: ['-flto'] + common_c_args,
    link_args: ['-flto'],
)

# Compiles with ASAN and coverage enabled.
coverage_flags = [
    '-fsanitize=address',
    '-fprofile-instr-generate',
    '-fcoverage-mapping',
]
executable(
    'crosid.test',
    src_files,
    c_args: coverage_flags + common_c_args,
    link_args: coverage_flags,
    native: true,
)
