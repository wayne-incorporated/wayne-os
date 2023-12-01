# Copyright 2018 The ChromiumOS Authors
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

EAPI=5

inherit appid cros-unibuild udev

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="-* amd64 x86"
IUSE="rammus-arc-r"
S="${WORKDIR}"

# Add dependencies on other ebuilds from within this board overlay
RDEPEND=""
DEPEND="
	${RDEPEND}
	chromeos-base/chromeos-config
"

src_install() {
	if use rammus-arc-r; then
		doappid "{89C62AB3-0C43-4833-8609-CEB56274747A}" "CHROMEBOOK"
	else
		doappid "{625849FA-56A0-4E67-9163-B89BE0C2A6AE}" "CHROMEBOOK"
	fi

	unibuild_install_files audio-files
	unibuild_install_files thermal-files

	udev_dorules "${FILESDIR}/99-chromeos-rammus-usb-charge-mode.rules"
}
