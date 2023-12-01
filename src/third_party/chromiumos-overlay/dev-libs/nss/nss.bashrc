# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Don't install the NSS CKFW SPI on target.
if [[ "$(cros_target)" == "target_image" ]]; then
  INSTALL_MASK+=" /usr/include/nss/*.api"
  PKG_INSTALL_MASK+=" /usr/include/nss/*.api"
fi
