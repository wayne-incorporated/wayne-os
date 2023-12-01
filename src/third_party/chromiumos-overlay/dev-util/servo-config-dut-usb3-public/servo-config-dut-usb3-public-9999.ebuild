# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the BSD license.

EAPI="7"

# This ebuild only cares about its own FILESDIR and ebuild file, so it tracks
# the canonical empty project.
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="../platform/empty-project"

inherit cros-workon

DESCRIPTION="List DUT USB 3 capability of Servo devices (public)."
LICENSE="BSD-Google"
KEYWORDS="~*"

src_install() {
	insinto /usr/share/servo
	doins "${FILESDIR}"/data/dut_usb3.no.public
	doins "${FILESDIR}"/data/dut_usb3.yes.public

	insinto /etc/servo
	doins "${FILESDIR}"/sysconf/dut_usb3.no
	doins "${FILESDIR}"/sysconf/dut_usb3.yes
}
