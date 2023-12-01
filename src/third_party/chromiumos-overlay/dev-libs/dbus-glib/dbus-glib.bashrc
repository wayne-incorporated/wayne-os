# Copyright 2017 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

cros_pre_src_prepare_dbus-glib_patches() {
	# TODO(benchan): Remove this patch once upstream gentoo picks up the patch.
	patch -p1 < "${BASHRC_FILESDIR}/${PN}-0.108-unused-function.patch" || die
}

# We need to manually specify a dbus-binding-tool when configuring for
# cross-compliation.
cros_pre_src_configure_dbus-glib_config() {
	[[ $(cros_target) == "cros_host" ]] && return 0
	EXTRA_ECONF+=" --with-dbus-binding-tool=dbus-binding-tool "
}

# To avoid wasting the disk space with unnecessary files.
cros_post_src_install_dbus-glib_remove_unnecessary_files() {
	# These files are useful only on host.
	if [[ $(cros_target) != "cros_host" ]]; then
		rm -f "${D}"/usr/bin/dbus-binding-tool || die
		rm -f "${D}"/usr/libexec/dbus-bash-completion-helper || die
	fi
}
