# Copyright 2014 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

iptables_mask="
  /sbin/iptables-apply
  /sbin/ip6tables-apply
"
PKG_INSTALL_MASK+=" ${iptables_mask}"
INSTALL_MASK+=" ${iptables_mask}"
unset iptables_mask
