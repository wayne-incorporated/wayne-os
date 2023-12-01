# Copyright 2023 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Punt setarch as we don't use it anywhere.
util_linux_mask="
  /usr/bin/i386
  /usr/bin/x86_64
  /usr/bin/linux32
  /usr/bin/linux64
  /usr/bin/setarch
  /usr/bin/uname26
"

# Punt support for filesystems we don't care about.
util_linux_mask+="
  /sbin/fsck.bfs
  /sbin/fsck.cramfs
  /sbin/fsck.minix
  /sbin/mkfs.bfs
  /sbin/mkfs.cramfs
  /sbin/mkfs.minix
"

# Punt esoteric programs.
util_linux_mask+="
  /sbin/raw
  /usr/bin/cytune
  /usr/bin/ddate
  /usr/bin/isosize
  /usr/sbin/fdformat
  /usr/sbin/tunelp
"

PKG_INSTALL_MASK+=" ${util_linux_mask}"
INSTALL_MASK+=" ${util_linux_mask}"
unset util_linux_mask

cros_pre_src_configure_custom_flags() {
	# Don't install setpriv -- people should use minijail0 instead.
	# Same for runuser.
	EXTRA_ECONF+=" --disable-setpriv --disable-runuser"
}

cros_post_src_install_unset_suid() {
	# bashrc runs in ebuild context, so declare vars to make shellcheck happy.
	: "${D?}"

	# Remove suid bit from all binaries installed by the package.
	# Neither of them have any practical use in ChromiumOS, but they
	# do present security risk.
	# Also remove the read permission. This was done by `preinst_sfperms()`
	# but it can't detect the files without the suid bit.
	find "${D}" -perm /4000 -exec einfo "Remove suid bit from" {} + \
				-exec chmod -s,go-r {} +
}
