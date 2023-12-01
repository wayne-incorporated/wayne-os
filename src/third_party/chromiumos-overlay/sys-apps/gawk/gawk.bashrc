# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

cros_pre_pkg_postinst_disable() {
	# pkg_postinst() in upstream package will try to set itself up as the
	# default awk provider. Don't let it do that for dev/test images, since
	# we want 'mawk' for that.
	[[ $(cros_target) != "cros_host" ]] && unset -f pkg_postinst
}
