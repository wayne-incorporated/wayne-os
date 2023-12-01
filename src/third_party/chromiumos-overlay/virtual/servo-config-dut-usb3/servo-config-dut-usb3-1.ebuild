# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the BSD license.
#
# This virtual package wraps:
#
#   dev-util/servo-config-dut-usb3-public
#   dev-util/servo-config-dut-usb3-private
#
# ...to hide the dependency awkwardness of selecting which to install.

EAPI="7"

DESCRIPTION="List DUT USB 3 capability of Servo devices (virtual)."
LICENSE="metapackage"
KEYWORDS="*"
IUSE="internal"
SLOT="0/${PVR}"

RDEPEND="
	dev-util/servo-config-dut-usb3-public:=
	internal? ( dev-util/servo-config-dut-usb3-private:= )
"
