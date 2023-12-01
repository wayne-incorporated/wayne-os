# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Install the experimental flatbuffers reflection schema.
# TODO(b/211717735): Remove this after the upstream feature request finished.
# https://github.com/google/flatbuffers/issues/7025
cros_post_src_install_reflection() {
	insinto /usr/include/flatbuffers
	doins reflection/reflection.fbs
}

# The flatbuffers compiler is only needed in the sdk, and saves space on the
# DUT.
cros_pre_src_configure_flatc() {
	if tc-is-cross-compiler; then
		# Don't install flatbuffers compiler onto the device.
		MYCMAKEARGS+=( -DFLATBUFFERS_BUILD_FLATC=0 )
	fi
}
