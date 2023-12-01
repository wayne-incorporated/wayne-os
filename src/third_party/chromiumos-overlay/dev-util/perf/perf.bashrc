# Copyright 2014 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Don't install libtraceevent plugins since the cross-compilation is broken in
# the perf package. See http://crbug.com/417137.
if [[ $(cros_target) != "cros_host" ]]; then
	perf_mask="
		/usr/lib*/traceevent/plugins/plugin_*.so
		/usr/lib/debug/usr/lib*/traceevent/plugins/plugin_*.so.debug
	"
	PKG_INSTALL_MASK+=" ${perf_mask}"
	INSTALL_MASK+=" ${perf_mask}"
	unset perf_mask
fi
