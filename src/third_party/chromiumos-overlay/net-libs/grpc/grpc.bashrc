# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# We only want plugins on the build machine.
if [[ $(cros_target) != "cros_host" ]]; then
  grpc_mask="
    /usr/bin/*plugin
  "
  PKG_INSTALL_MASK+=" ${grpc_mask}"
  INSTALL_MASK+=" ${grpc_mask}"
  unset grpc_mask
fi
