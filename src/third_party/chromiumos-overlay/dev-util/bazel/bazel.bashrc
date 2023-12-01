# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Provide correct std lib linking flag when compiling with Clang. Bazel uses
# clang (not clang++) even when compiling C++ code, which fails to link with
# the correct standard library without manual intervention. See
# crbug.com/820295. 
cros_pre_src_configure_stdlib_linkflag() {
	tc-is-clang && LDFLAGS="${LDFLAGS} -lc++"
}
