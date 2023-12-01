# Copyright 2010 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=6

DESCRIPTION="Das U-Boot boot scripts"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""

RDEPEND="chromeos-base/u-boot-license"
S=${WORKDIR}

src_compile() {
	local base="${FILESDIR}"/boot.scr
	sed 's/\${KERNEL_PART}/2/g;s/\${ROOT_PART}/3/g' "${base}" >boot-A.scr || die
	sed 's/\${KERNEL_PART}/4/g;s/\${ROOT_PART}/5/g' "${base}" >boot-B.scr || die

	local script
	for script in boot-{A,B}.scr; do
		mkimage -O linux -T script -C none -a 0 -e 0 \
			-n "${script}" -d "${script}" "${script}.uimg" >/dev/null || die
	done
}

src_install() {
	insinto /boot
	doins boot-{A,B}.scr.uimg
}
