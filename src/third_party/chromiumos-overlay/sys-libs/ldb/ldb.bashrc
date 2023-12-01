# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# ldb does not build with sanitizer flags, https://crbug.com/841887.
cros_pre_src_prepare_filter_sanitizers() {
	filter_sanitizers
}

# Adds a hook to pre_src_prepare to override the arguments to WAF
# in order to support cross compilation.
cros_pre_src_prepare_cross() {
	case "${ARCH}" in
		"amd64")
			# No need to cross compile for this case.
			;;
		"arm" | "arm64")
			local waf="${T}/waf"
			cat<<EOF>"${waf}"
			#!/bin/sh
			# WAF_BINARY must be set from the ebuild.
			exec "${WAF_BINARY}" "\$@" --cross-compile --cross-answers="${BASHRC_FILESDIR}/${ARCH}_waf_config_answers"
EOF

			chmod a+rx "${waf}"
			WAF_BINARY="${waf}"
			;;
		*)
			die "${P} does not support cross-compiling for ${ARCH}"
			;;
	esac
}
