# Copyright 2022 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=7

inherit appid cros-unibuild cros-workon udev

# This ebuild only cares about its own FILESDIR and ebuild file, so it tracks
# the canonical empty project.
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="platform/empty-project"

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* ~arm64 ~arm"
IUSE="strongbad-kernelnext strongbad-userdebug"

RDEPEND="
	chromeos-base/chromeos-bsp-baseboard-trogdor
"
DEPEND="${RDEPEND}"

src_install() {
	if use strongbad-kernelnext; then
		doappid "{CAF7DF76-5722-4B6F-9994-D7D222F191D7}" "CHROMEBOOK"
	elif use strongbad-userdebug; then
		doappid "{9B15802E-94AF-24C2-5DC4-D9A3A80E0FF5}" "CHROMEBOOK"
	else
		doappid "{ABD68995-5A83-31CA-9AC6-49D8194EEA52}" "CHROMEBOOK"
	fi

	# Install a rule tagging keyboard as internal
	udev_dorules "${FILESDIR}/91-hammer-keyboard.rules"

	# Install hammerd udev rules and override for chromeos-base/hammerd.
	udev_dorules "${FILESDIR}/99-hammerd.rules"

	# Install udev rule to keep the USB hub always powered during system suspend.
	udev_dorules "${FILESDIR}/99-usb-hub-power.rules"

	# Install audio config
	unibuild_install_files audio-files

	# Install semtech configuration files
	unibuild_install_files proximity-sensor-files
}
