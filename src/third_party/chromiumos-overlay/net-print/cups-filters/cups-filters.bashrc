# Copyright 2016 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

cups_filters_mask="
  /usr/share/cups/drv
  /usr/share/cups/ppdc
"

PKG_INSTALL_MASK+=" ${cups_filters_mask}"
INSTALL_MASK+=" ${cups_filters_mask}"

unset cups_filters_mask

cros_pre_src_prepare_enable_cxx_exceptions() {
	cros_enable_cxx_exceptions
}
