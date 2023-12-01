# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="platform/empty-project"

inherit arc-build-constants cros-unibuild cros-workon

DESCRIPTION="Install codec configuration for ARCVM"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="~*"
IUSE=""

RDEPEND="!chromeos-base/arcvm-codec-software"

src_install() {
	arc-build-constants-configure
	insinto "${ARC_VM_VENDOR_DIR}/etc/"
	doins "${FILESDIR}"/*
}
