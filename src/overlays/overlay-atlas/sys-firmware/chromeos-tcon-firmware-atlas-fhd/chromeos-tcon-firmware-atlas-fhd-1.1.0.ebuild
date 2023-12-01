# Copyright 2020 The ChromiumOS Authors
# This file distributed under the terms of the BSD license.
#
# Package version scheme: <major_ver>.<minor_ver>.<tarball_ver>-r<ebuild_rev>
# All package version numbers are in decimal.
# Example: 1.4.0-r1
#
# major_ver is from DPCD0040Ah
# minor_ver is from DPCD0040Bh
# See: https://issuetracker.google.com/123000266
#
# tarball_ver represents version of the tarball for the given major+minor
# version.  Start at 0 for first tarball of a given FW+CFG version.  Increment
# only when changing the tarball while keeping the actual firmware the same.
#
# ebuild_rev represents version of this ebuild file for the given tarball.
# Start at 1 for first ebuild revision of a given tarball.  Increment only when
# changing this ebuild without changing the tarball.
#
# All package version changes should be performed by adding or renaming
# symlinks.  This actual ebuild file name should never need to change, unless
# renaming the package.

EAPI="7"

DESCRIPTION="Atlas FHD display TCON (Timing Controller) firmware payload."
SRC_URI="gs://chromeos-localmirror/distfiles/${P}.tar.xz"

LICENSE="LICENSE.atlas-tcon-firmware"
SLOT="0"
KEYWORDS="*"

S="${WORKDIR}"

src_install() {
	local fw_res=
	local fw_major_hex=
	local fw_minor_hex=
	local fw_fname=
	local fw_symlink=

	fw_res="${PN##*-}"
	fw_major_hex="$(printf '0x%02X' "$(ver_cut 1)")"
	fw_minor_hex="$(printf '0x%02X' "$(ver_cut 2)")"
	fw_fname="nvt_tcon_fw_${fw_res}_${fw_major_hex}_${fw_minor_hex}.bin"
	fw_symlink="nvt_tcon_firmware_${fw_res}.bin"

	insinto /opt/google/tcon/firmware
	doins "${P}/${fw_fname}"

	# Create symlink at /lib/firmware to the firmware binary.
	dosym "/opt/google/tcon/firmware/${fw_fname}" "/lib/firmware/${fw_symlink}"
}
