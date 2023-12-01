# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=5

inherit udev

DESCRIPTION="Scripts to rescan the pci bus and revive wifi (See b/35648315)"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"

RDEPEND="
	!<chromeos-base/chromeos-bsp-cyan-0.0.2-r14
"
DEPEND="${RDEPEND}"

S="${WORKDIR}"

src_install() {
	# Add udev rule for iwlwifi workaround for Intel NIC
	# disappearing from PCI bus
	udev_dorules "${FILESDIR}/60-iwlwifi.rules"
	exeinto "$(get_udevdir)"
	doexe "${FILESDIR}/log-wifi-gone-metric.sh"

	# Add an upstart script that will monitor wifi status
	# once the workaround (pci rescan) to revive wifi has been applied
	insinto "/etc/init"
	doins "${FILESDIR}/pci-rescan-to-revive-wifi.conf"

	# Add script that does the actual rescan and metrics logging
	# and is called by the upstart .conf
	dosbin "${FILESDIR}/pci-rescan-to-revive-wifi.sh"

	# Set the iwlwifi module parameters.
	insinto "/etc/modprobe.d"
	doins "${FILESDIR}/modprobe.d/iwlwifi_remove_when_gone.conf"
}
