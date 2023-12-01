# Copyright 2020 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Remove files that will not be used from targets.
# /etc/lvm/lvm.conf is added by chromeos-init.
# dmeventd's function is already handled by platform2 packages.
if [[ $(cros_target) != "cros_host" ]]; then
  lvm_mask="
    /etc/dmtab
    /etc/lvm/lvm.conf
    /etc/lvm/profile/*
    /lib*/liblvm2app.so*
    /lib/udev/rules.d/11-dm-lvm.rules
    /lib/udev/rules.d/69-dm-lvm-metad.rules
    /usr/lib*/liblvm2app.so*
    /usr/lib*/pkgconfig/lvm2app.pc
    /usr/lib/tmpfiles.d/lvm2.conf
    /usr/include/lvm2app.h
    /sbin/dmeventd
    /sbin/lvmetad
    /sbin/lvpolld
  "

  PKG_INSTALL_MASK+=" ${lvm_mask}"
  INSTALL_MASK+=" ${lvm_mask}"
  unset lvm_mask
fi
