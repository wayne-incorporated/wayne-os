# Copyright 2014 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Use the ucm files installed by media-sound/adhd.
if [[ $(cros_target) != "cros_host" ]] ; then
	alsalib_mask="
		/usr/share/alsa/ucm/DAISY-I2S
		/usr/share/alsa/ucm/chtrt5645/
		/usr/share/alsa/ucm/chtrt5645/chtrt5645.conf
		/usr/share/alsa/ucm/chtrt5645/HiFi.conf
	"
	PKG_INSTALL_MASK+=" ${alsalib_mask}"
	INSTALL_MASK+=" ${alsalib_mask}"
	unset alsalib_mask
fi
