# Copyright 2021 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Don't install built-in SSH/SFTP DNS-SD service definitions
avahi_mask="/etc/avahi/services/ssh.service"
avahi_mask+=" /etc/avahi/services/sftp-ssh.service"

# Don't install the default config file in the package since chromeos-base
# will provide a ChromeOS-specific configuration file
avahi_mask+=" /etc/avahi/avahi-daemon.conf"

# We don't use avahi-dnsconfd, so no need for its action script
avahi_mask+=" /etc/avahi/avahi-dnsconfd.action"

INSTALL_MASK+=" ${avahi_mask}"
PKG_INSTALL_MASK+=" ${avahi_mask}"
unset avahi_mask

cros_post_src_install_avahi_nls() {
	# Even if we build w/USE=-nls, avahi forces it back on when glib is
	# enabled.  Forcibly punt the translations since we never use them.
	rm -rf "${D}"/usr/share/locale
}
