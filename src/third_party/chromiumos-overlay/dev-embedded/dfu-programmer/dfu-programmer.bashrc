# Copyright 2016 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Mask the udev rules which are not compatible with Chrome OS.
rules_mask="
  /lib/udev/rules.d/70-dfu-programmer.rules
"

PKG_INSTALL_MASK+=" ${rules_mask}"
INSTALL_MASK+=" ${rules_mask}"
unset rules_mask
