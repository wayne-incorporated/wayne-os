# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

# @ECLASS: coreboot-private-files.eclass
# @MAINTAINER:
# The ChromiumOS Authors
# @BLURB: Unifies logic for installing private coreboot files.

# Check for EAPI 4+
case "${EAPI:-0}" in
4|5|6|7) ;;
*) die "unsupported EAPI (${EAPI}) in eclass (${ECLASS})" ;;
esac

coreboot-private-files_src_install() {
	local srcdir="${1:-${FILESDIR}}"
	insinto /firmware/coreboot-private
	local file
	while read -d $'\0' -r file; do
		# This file should never be installed and is only used by the
		# cros_workon uprev script.
		if [[ "${file}" == "${FILESDIR}/chromeos-version.sh" ]]; then
			continue;
		fi
		doins -r "${file}"
	done < <(find -H "${srcdir}" -maxdepth 1 -mindepth 1 -print0)
}

EXPORT_FUNCTIONS src_install
