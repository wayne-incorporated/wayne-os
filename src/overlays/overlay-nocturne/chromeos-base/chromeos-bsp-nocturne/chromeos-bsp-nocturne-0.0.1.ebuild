# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=5

inherit appid udev cros-audio-configs

DESCRIPTION="Nocturne board-specific ebuild that pulls in necessary ebuilds as
dependencies or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* amd64 x86"
IUSE="nocturne-kernelnext kernel-4_4"
S="${WORKDIR}"

# Add dependencies on other ebuilds from within this board overlay
DEPEND="
	chromeos-base/chromeos-bsp-baseboard-krabbylake
"

RDEPEND="${DEPEND}"

src_install() {
	if use nocturne-kernelnext; then
		doappid "{A6F41340-9B74-11EB-ABA4-CF8257BA5A2C}" "CHROMEBOOK"
	else
		doappid "{BD7F7139-CC18-49C1-A847-33F155CCBCA8}" "CHROMEBOOK"
	fi

	# Install platform specific config files for power_manager.
	insinto "/usr/share/power_manager/board_specific"
	doins "${FILESDIR}"/powerd_prefs/*

	# Override for chromeos-base/hammerd.
	insinto /etc/init
	doins "${FILESDIR}/hammerd.override"

	# Install audio config files
	if ! use kernel-4_4; then
		local audio_config_dir="${FILESDIR}/kernelnext-audio-config"
	else
		local audio_config_dir="${FILESDIR}/audio-config"
	fi
	install_audio_configs nocturne "${audio_config_dir}"

	# Install modprobe.d conf for dmic modeswitch delay
	insinto /etc/modprobe.d
	doins "${FILESDIR}"/snd_soc_dmic.conf

	# Install device specific udev rules.
	udev_dorules "${FILESDIR}"/udev/*.rules

	# Install /etc/init/generate_rdc_update.conf, which reads DSM calibration
	# data from VPD and writes to /run/cras/rdc_update.bin
	insinto /etc/init
	doins "${FILESDIR}"/init/generate_rdc_update.conf

	# Install device-specific automatic brightness model parameters.
	insinto "/usr/share/chromeos-assets/autobrightness"
	doins "${FILESDIR}/autobrightness/model_params.json"
}
