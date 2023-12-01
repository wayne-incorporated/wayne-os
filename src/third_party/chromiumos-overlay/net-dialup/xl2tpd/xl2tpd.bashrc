# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

xl2tpd_mask="
  /usr/lib/tmpfiles.d/xl2tpd.conf
"

PKG_INSTALL_MASK+=" ${xl2tpd_mask}"
INSTALL_MASK+=" ${xl2tpd_mask}"
