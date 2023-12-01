# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

if [[ $(cros_target) == "target_image" ]]; then
	libtirpc_headers_mask="
		/usr/include/tirpc/*/*.x
	"
	PKG_INSTALL_MASK+=" ${libtirpc_headers_mask}"
	INSTALL_MASK+=" ${libtirpc_headers_mask}"
	unset libtirpc_headers_mask
fi
