# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Always build sed w/sandbox enabled for boards to avoid arbitrary code exec.
cros_post_src_prepare_force_sandbox() {
	if [[ $(cros_target) != "cros_host" ]]; then
		# Upstream doesn't want to add a configure flag for this.
		# https://lists.gnu.org/archive/html/bug-sed/2018-03/msg00001.html
		sed -i \
			-e '/^bool sandbox = false;/s:false:true:' \
			sed/sed.c || die
		# Make sure the sed took.
		grep -q '^bool sandbox = true;' sed/sed.c || die "forcing sandbox failed"
	fi
}
