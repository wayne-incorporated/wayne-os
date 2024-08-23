# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit appid cros-workon

CROS_WORKON_PROJECT="chromiumos/infra/build/empty-project"
CROS_WORKON_LOCALNAME="platform/empty-project"

DESCRIPTION="Ebuild which pulls in any necessary ebuilds as dependencies
or portage actions."

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="~*"

RDEPEND="
	!<chromeos-base/gestures-conf-0.0.2
	!<chromeos-base/chromeos-bsp-reven-private-0.0.1-r20
	chromeos-base/flex_hwis
	chromeos-base/reven-hwdb
	chromeos-base/reven-quirks
	sys-firmware/fwupd-uefi-dbx
"

src_install() {
	insinto "/etc/gesture"
	doins "${FILESDIR}"/gesture/*

	doappid "{C924E0C4-AF80-4B6B-A6F0-DD75EDBCC37C}" "CHROMEBOOK"
}
