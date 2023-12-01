# Copyright 2016 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

cros_post_src_configure_custom_config() {
  local config
  # Enable additional pending commands: dd, modprobe, tar.
  for config in DD MODPROBE TAR; do
    sed -i "s/^# CONFIG_${config} is not set/CONFIG_${config}=y/" \
      "${S}/.config" || die "toybox config ${config} changed unexpectedly!"
  done

  emake oldconfig
}
