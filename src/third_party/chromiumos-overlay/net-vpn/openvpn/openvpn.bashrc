# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Remove unused shell scripts from upstream ebuild.
openvpn_mask="
  /etc/openvpn/up.sh
  /etc/openvpn/down.sh
"

PKG_INSTALL_MASK+=" ${openvpn_mask}"
INSTALL_MASK+=" ${openvpn_mask}"
unset openvpn_mask
