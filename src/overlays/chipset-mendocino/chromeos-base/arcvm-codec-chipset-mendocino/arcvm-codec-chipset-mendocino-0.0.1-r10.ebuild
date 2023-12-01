# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_WORKON_COMMIT="d2d95e8af89939f893b1443135497c1f5572aebc"
CROS_WORKON_TREE="776139a53bc86333de8672a51ed7879e75909ac9"
CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="platform/empty-project"

inherit arc-build-constants cros-unibuild cros-workon

DESCRIPTION="Install codec configuration for ARCVM"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""

RDEPEND="!chromeos-base/arcvm-codec-software"

src_install() {
	arc-build-constants-configure
	insinto "${ARC_VM_VENDOR_DIR}/etc/"
	doins "${FILESDIR}"/*
}
