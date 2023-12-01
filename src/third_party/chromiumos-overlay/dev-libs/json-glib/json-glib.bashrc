# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Disable Wpointer-to-int-cast warning in json-glib, https://crbug.com/1054099.

# This library goes out of its way to turn on this warning and then
# has that exact error.  We used to disable the warning by setting
# -Wno-pointer-to-int-cast, but we can't rely on that being added
# after the libraries own flags.  Instead, just yank the flag out of
# the meson build file.

cros_pre_src_configure_disable_warnings() {
	sed -i -e "/-Werror=pointer-to-int-cast/d" "${S}/meson.build" || die
}
