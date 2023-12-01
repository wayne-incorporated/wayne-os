# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# TODO(b/202989467): Temporarily removed "-Wa,-march=all" untill clang
# crash in gnutls build is fixed.
cros_pre_src_prepare_disable_wa_marchall() {
	sed -i 's/-Wa,-march=all//g' \
		"${S}/lib/accelerated/aarch64/Makefile.in" || die
}
