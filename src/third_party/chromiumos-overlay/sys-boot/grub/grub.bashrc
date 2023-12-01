# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

PKG_INSTALL_MASK+=" /etc/grub.d/00_header
                    /etc/grub.d/10_linux
                    /etc/grub.d/30_os-prober
                    /etc/grub.d/40_custom
                    /etc/grub.d/README
                    /lib64/grub/grub-mkconfig_lib
                    /lib64/grub/update-grub_lib"
INSTALL_MASK+=" /etc/grub.d/00_header
                /etc/grub.d/10_linux
                /etc/grub.d/30_os-prober
                /etc/grub.d/40_custom
                /etc/grub.d/README
                /lib64/grub/grub-mkconfig_lib
                /lib64/grub/update-grub_lib"
