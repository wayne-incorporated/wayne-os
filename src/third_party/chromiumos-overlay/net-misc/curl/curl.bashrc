# Copyright 2016 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
#
# With clang-FORTIFY enabled, this package fails to configure. We currently
# have a patch in review for sys-devel/crossdev that will fix this issue. Until
# we can pull that back, we just disable clang's FORTIFY. Note that this
# doesn't disable FORTIFY entirely; it just disables the enhanced,
# clang-specific version.

export CPPFLAGS+=' -D_CLANG_FORTIFY_DISABLE '

cros_pre_src_configure_curl_flags() {
	# Disable unused protocols to minimize unnecessary attack surface:
	EXTRA_ECONF+="
		--disable-gopher
		--disable-imap
		--disable-pop3
		--disable-rtsp
		--disable-smtp
		--disable-telnet
		--disable-tftp
	"
}