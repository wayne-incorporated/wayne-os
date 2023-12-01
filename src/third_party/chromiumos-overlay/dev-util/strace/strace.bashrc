# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Disable mpers on arm64, https://crbug.com/844002 .
cros_pre_src_configure_check_mpers() {
	if [[ "${CHOST}" == aarch64* ]]; then
		EXTRA_ECONF+=" --disable-mpers"
	fi
}
