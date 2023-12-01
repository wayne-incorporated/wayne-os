# Copyright 2019 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# These are only used at build time.
if [[ $(cros_target) != "cros_host" ]]; then
	timezone_mask="
		/usr/bin/tzselect
		/usr/bin/zdump
		/usr/bin/zic
	"
	PKG_INSTALL_MASK+=" ${timezone_mask}"
	INSTALL_MASK+=" ${timezone_mask}"
	unset timezone_mask

	# Disable default timezone selection.  The chromeos-base package will
	# create a symlink at /etc/localtime instead.
	get_TIMEZONE() { return 1; }
fi
