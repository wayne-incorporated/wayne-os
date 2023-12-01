# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# The sqlite tool isn't needed but causes problems, see crbug.com/915827.
if [[ $(cros_target) != "cros_host" ]]; then
  sqlite_mask="
    /usr/bin/sqlite*
  "
  PKG_INSTALL_MASK+=" ${sqlite_mask}"
  INSTALL_MASK+=" ${sqlite_mask}"
  unset sqlite_mask
fi

# Sqlite is hot, so we should be optimizing it for speed.
cros_pre_src_prepare_enable_optimizations() {
  cros_optimize_package_for_speed
}
