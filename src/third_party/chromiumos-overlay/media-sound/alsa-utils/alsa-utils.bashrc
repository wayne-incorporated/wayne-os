# Copyright 2014 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Remove .wav test files used by `speaker-test -t wav` from the image.
alsa_mask="/usr/share/sounds/alsa/*.wav"
# Remove unused diagnostic tool that requires bash.
alsa_mask+=" /usr/sbin/alsa-info.sh"
# Remove restore logic, as it's unused and just logs errors at boot.
alsa_mask+=" /lib/udev/rules.d/90-alsa-restore.rules"
INSTALL_MASK+=" ${alsa_mask}"
PKG_INSTALL_MASK+=" ${alsa_mask}"
unset alsa_mask
