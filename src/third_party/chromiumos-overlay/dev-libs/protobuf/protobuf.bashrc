# Copyright 2014 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# We install these with our chromeos-base package.
if [[ $(cros_target) != "cros_host" ]]; then
  protobuf_mask="
    /usr/bin/protoc
    /usr/lib*/libprotoc.so*
  "
  PKG_INSTALL_MASK+=" ${protobuf_mask}"
  INSTALL_MASK+=" ${protobuf_mask}"
  unset protobuf_mask
fi

if [[ $(cros_target) == "target_image" ]]; then
  protobuf_mask="
    /usr/include/google/protobuf/*.inc
  "
  PKG_INSTALL_MASK+=" ${protobuf_mask}"
  INSTALL_MASK+=" ${protobuf_mask}"
  unset protobuf_mask
fi
