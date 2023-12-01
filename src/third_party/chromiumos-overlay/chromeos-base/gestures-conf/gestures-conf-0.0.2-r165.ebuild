# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
CROS_WORKON_COMMIT="a9ae9e797b261031e82fbc3fd58a867f1e617929"
CROS_WORKON_TREE="220a1b20edcbdabee954dcbbe8a99c917761031c"
CROS_WORKON_LOCALNAME="platform/xorg-conf"
CROS_WORKON_PROJECT="chromiumos/platform/xorg-conf"
CROS_WORKON_OUTOFTREE_BUILD=1

inherit cros-workon

DESCRIPTION="Gestures library configuration files"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/xorg-conf/"
SRC_URI=""

LICENSE="BSD-Google"
KEYWORDS="*"

RDEPEND="!chromeos-base/touchpad-linearity"
DEPEND=""

src_install() {
	insinto /etc/gesture

	doins 20-mouse.conf
	doins 40-touchpad-cmt.conf
}
