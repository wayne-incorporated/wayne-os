# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Force installing tiny_ssim until https://bugs.gentoo.org/756754 is addressed.
cros_post_src_install_tools() {
	install_progs() {
		multilib_is_native_abi && dobin "${BUILD_DIR}"/tools/tiny_ssim
	}
	multilib_foreach_abi install_progs
}
