# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=5

inherit udev user

DESCRIPTION="Ebuild to support the Chrome OS Cr50 device."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE="generic_tpm2 cr50_onboard ti50_onboard cr50_disable_sleep_in_suspend"

RDEPEND="
	chromeos-base/ec-utils
	chromeos-base/vboot_reference:=
	!<chromeos-base/chromeos-cr50-0.0.1-r38
"

S="${WORKDIR}"

pkg_preinst() {
	enewuser "rma_fw_keeper"
	enewgroup "rma_fw_keeper"
	enewgroup "suzy-q"
}

src_install() {
	local files
	local f

	insinto /etc/init
	files=(
		cr50-metrics.conf
		cr50-result.conf
		cr50-update.conf
	)
	for f in "${files[@]}"; do
		doins "${FILESDIR}/${f}"
	done

	if use cr50_disable_sleep_in_suspend; then
		doins "${FILESDIR}/cr50-disable-sleep.conf"
	fi

	udev_dorules "${FILESDIR}"/99-cr50.rules

	exeinto /usr/share/cros
	files=(
		cr50-disable-sleep.sh
		cr50-flash-log.sh
		cr50-get-name.sh
		cr50-read-rma-sn-bits.sh
		cr50-reset.sh
		cr50-set-board-id.sh
		cr50-set-sn-bits.sh
		cr50-update.sh
		cr50-verify-ro.sh
		tpm2-lock-space.sh
		tpm2-nv-utils.sh
		tpm2-read-board-id.sh
		tpm2-read-space.sh
		tpm2-write-space.sh
	)
	for f in "${files[@]}"; do
		doexe "${FILESDIR}/${f}"
	if use generic_tpm2; then
		sed -i 's/PLATFORM_INDEX=false/PLATFORM_INDEX=true/' \
			"${D}/usr/share/cros/${f}" ||
			die "Can't set PLATFORM_INDEX to true for ${f}"
	fi
	done

	if use ti50_onboard; then
		f="ti50-constants.sh"
	elif use cr50_onboard || use generic_tpm2; then
		f="cr50-constants.sh"
	else
		die "Neither GSC nor generic TPM2 is used"
	fi
	newexe "${FILESDIR}/${f}" "gsc-constants.sh"

	insinto /opt/google/cr50/ro_db
	doins "${FILESDIR}"/ro_db/*.db
}
