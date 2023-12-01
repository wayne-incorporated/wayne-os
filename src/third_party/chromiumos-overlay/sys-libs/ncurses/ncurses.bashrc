# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Building ncurses with sanitizers break chrooting, https://crbug.com/843301.
cros_pre_src_prepare_filter_sanitizers() {
	filter_sanitizers
}

cros_post_src_install_terminfo() {
	pushd "${D}" >/dev/null || die

	# Make sure the terminal crosh uses is available in the rootfs.
	if [[ ${SLOT%/*} == "0" ]]; then
		mkdir -p etc/terminfo/h || die
		mv -i usr/share/terminfo/h/hterm{,-256color} etc/terminfo/h/ || die

		# Delete all the other terminfos since we don't need them.
		rm -r usr/share/terminfo/ || die
		rm -f usr/lib*/terminfo || die
	fi

	popd >/dev/null
}
