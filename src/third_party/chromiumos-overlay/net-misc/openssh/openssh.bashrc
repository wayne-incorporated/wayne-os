# Copyright 2012 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# We install these with our chromeos-base package.
if [[ $(cros_target) != "cros_host" ]]; then
	openssh_mask="
		/etc/ssh/ssh_config
		/etc/ssh/sshd_config
		/usr/lib*/misc/ssh-keysign
	"
	PKG_INSTALL_MASK+=" ${openssh_mask}"
	INSTALL_MASK+=" ${openssh_mask}"
	unset openssh_mask
fi

PKG_INSTALL_MASK+=" /var/empty"
INSTALL_MASK+=" /var/empty"

cros_pre_src_configure_openssh_flags() {
	# Use /mnt/empty instead of /var/empty as the privsep path so that the path
	# doesn't need to be created at runtime and will already be read only.
	EXTRA_ECONF+="
		--with-privsep-path='${EPREFIX}/mnt/empty'
	"

	# For most installs, openssh ends up in ROOT=/.  That means all of its
	# helpers end up in /usr/bin (like scp/sftp).  For embedded systems, we
	# like to omit ssh in ROOT=/ and instead only install it for dev images
	# which means it ends up in ROOT=/usr/local.  If you try to scp or sftp
	# to the device, it'll fail to find the helper programs.
	#
	# Update the compiled-in PATH value so that things work whether openssh
	# lives in / or /usr/local.  Since ssh only gets used in developer mode,
	# this shouldn't be exposing any security issues.
	local path='/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/usr/local/sbin'
	EXTRA_ECONF+="
		--with-default-path=${path}
		--with-superuser-path=${path}
	"
}
