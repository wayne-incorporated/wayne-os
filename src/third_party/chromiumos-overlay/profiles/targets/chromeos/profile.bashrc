# Copyright 2011 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Locate all the old style config scripts this package installs.  Do it here
# here so we can search the temp $D which has only this pkg rather than the
# full ROOT which has everyone's files.
cros_pre_pkg_preinst_wrap_old_config_scripts() {
	# Only wrap when installing into a board sysroot.
	[[ $(cros_target) != "board_sysroot" ]] && return 0

	# bashrc runs in ebuild context, so declare vars to make shellcheck happy.
	: "${D?}" "${CHOST?}" "${CROS_BUILD_BOARD_TREE?}" "${CROS_ADDONS_TREE?}"

	# Ignore $CHOST- prefix as some packages create that inaddition to the unprefixed.
	local wrappers
	mapfile -d '' wrappers < <(
		find "${D}"/usr/bin/ \
			'!' -name "${CHOST}-*" -name '*-config' \
			-printf '%P\0' 2>/dev/null
	)

	local wdir="${CROS_BUILD_BOARD_TREE}/bin"
	mkdir -p "${wdir}"

	local c w
	for w in "${wrappers[@]}" ; do
		w="${wdir}/${CHOST}-${w}"
		c="${CROS_ADDONS_TREE}/scripts/config_wrapper"
		if [[ ! -e ${w} ]] ; then
			ln -s "${c}" "${w}"
		fi
	done
}
