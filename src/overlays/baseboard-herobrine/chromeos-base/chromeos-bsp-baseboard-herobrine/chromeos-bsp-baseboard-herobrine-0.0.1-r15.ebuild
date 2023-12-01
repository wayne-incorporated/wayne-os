# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="d2d95e8af89939f893b1443135497c1f5572aebc"
CROS_WORKON_TREE="776139a53bc86333de8672a51ed7879e75909ac9"
inherit arc-build-constants cros-workon udev

# This ebuild only cares about its own FILESDIR and ebuild file, so it tracks
# the canonical empty project.
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="platform/empty-project"

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* arm64 arm"
IUSE="arcvm cheets modemfwd"

RDEPEND="
	modemfwd? ( chromeos-base/modemfwd-helpers-herobrine )
	net-misc/rmtfs
	net-misc/qc-netmgr
"
DEPEND="${RDEPEND}"

src_install() {
	insinto "/etc"
	# Override default CPU clock speed governor.
	doins "${FILESDIR}/cpufreq.conf"
	# Use 'step_wise' governor for GPU thermal zones.
	doins "${FILESDIR}/thermal_zone.conf"

	# Install cpuset adjustments.
	if use cheets; then
		arc-build-constants-configure

		insinto "${ARC_PREFIX:?}/vendor/etc/init"
		doins "${FILESDIR}/init.cpusets.rc"
		# See b/161399876:
		if use arcvm; then
			doins "${FILESDIR}/arcvm/arc-sf-config.rc"
		else
			doins "${FILESDIR}/arcpp/arc-sf-config.rc"
		fi
	fi

	# udev rules for codecs
	insinto /etc/init
	doins "${FILESDIR}/udev-trigger-codec.conf"
	udev_dorules "${FILESDIR}/50-media.rules"

	# udev rules to enable USB wakeup
	udev_dorules "${FILESDIR}/99-usb-wakeup.rules"

	# udev rule to enable wakeup for smp2p devices
	udev_dorules "${FILESDIR}/99-qcom-smp2p-wakeup.rules"

	# udev rule to set the RPS mask of the modem network interfaces
	udev_dorules "${FILESDIR}/99-mmdata-mgr.rules"

	# Install modem FSG verification init script
	insinto "/etc/init"
	doins "${FILESDIR}/verify_fsg.conf"
	exeinto /usr/share/cros/init
	doexe "${FILESDIR}/verify_fsg.sh"
}
