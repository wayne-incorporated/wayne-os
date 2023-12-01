# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

FACTORY_DIR="/mnt/stateful_partition/dev_image/factory"

is_factory_test_mode() {
  # The path to factory enabled tag. If this path exists in a debug build,
  # we assume factory test mode.
  local factory_tag_path="${FACTORY_DIR}/enabled"
  crossystem "debug_build?1" && [ -f "${factory_tag_path}" ]
}

is_factory_installer_mode() {
  grep -wq 'cros_factory_install' /proc/cmdline || \
    [ -f /root/.factory_installer ]
}

is_factory_mode() {
  is_factory_test_mode || is_factory_installer_mode
}
