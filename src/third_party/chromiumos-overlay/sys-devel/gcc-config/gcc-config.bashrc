# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

cros_post_pkg_postinst_clang_cc() {
	# Point cc and cpp to clang based tools instead of gcc.
	ln -sf "/usr/bin/clang_cc_wrapper" "/usr/bin/cc"
	ln -sf "/usr/bin/clang-cpp" "/usr/bin/cpp"
}
