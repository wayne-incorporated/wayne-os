# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="6"

DESCRIPTION="List of packages that are needed for Chrome OS factory software."
HOMEPAGE="http://dev.chromium.org/"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE="+cras +shill"

################################################################################

# Packages for factory framework ("Goofy"):
FACTORY_FRAMEWORK_RDEPEND="
	shill? ( chromeos-base/shill-test-scripts )
	dev-lang/python
	dev-python/dbus-python
	dev-python/dpkt
	dev-python/jsonrpclib
	dev-python/jsonschema
	dev-python/netifaces
	dev-python/pyyaml
	dev-python/setproctitle
	dev-python/ws4py
"
# Note: dbus-python may be temporarily broken on embedded platform.

# Packages shared by several pytests inside factory.
FACTORY_TEST_RDEPEND="
	app-arch/lbzip2
	app-arch/pigz
	app-arch/xz-utils
	dev-python/numpy
	dev-python/pyserial
	dev-python/python-evdev
	dev-python/python-gnupg
	dev-python/pyudev
	dev-python/requests
	dev-util/stressapptest
	net-misc/htpdate
	sys-apps/iproute2
	sys-apps/lshw
	sys-apps/mosys
"

# Packages used by audio related tests
FACTORY_TEST_RDEPEND+="
	cras? (
		chromeos-base/audiotest
		media-sound/sox
	)
"

# Packages used by camera related tests
FACTORY_TEST_RDEPEND+="
	media-gfx/zbar
	media-libs/opencv
"

# Packages used by removable storage test.
FACTORY_TEST_RDEPEND+="
	sys-block/parted
"

# Packages used by network related tests.
FACTORY_TEST_RDEPEND+="
	dev-python/pexpect
	net-misc/iperf:3
"

# Packages used by registration code tests.
FACTORY_TEST_RDEPEND+="
	dev-python/protobuf-python
"

# Packages to support running autotest tests inside factory framework.
FACTORY_TEST_RDEPEND+="
	chromeos-base/autotest-client
"

# Packages for a rich set of general system commands.
FACTORY_TEST_RDEPEND+="
	sys-apps/busybox
	sys-apps/toybox
"

# Packages used by finalize.
FACTORY_TEST_RDEPEND+="
	sys-apps/coreboot-utils
"

# Packages used to generate QR codes.
FACTORY_TEST_RDEPEND+="
	dev-python/qrcode
"

# Packages used to read config.binaryproto.
FACTORY_TEST_RDEPEND+="
	chromeos-base/cros-config-api
"

# Packages used for Widevine keybox provisioning tests.
FACTORY_TEST_RDEPEND+="
	dev-python/crcmod
	dev-python/pycryptodome
"

################################################################################
# Assemble the final RDEPEND variable for portage
################################################################################
RDEPEND="${FACTORY_FRAMEWORK_RDEPEND}
	 ${FACTORY_TEST_RDEPEND}
"
