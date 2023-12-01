# Copyright 2013 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Unmount bind mounts for /var and /home/chronos.
umount_var_and_home_chronos() {
  umount -n /var /home/chronos
}
