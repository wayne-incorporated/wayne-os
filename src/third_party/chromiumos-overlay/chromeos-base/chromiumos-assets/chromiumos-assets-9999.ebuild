# Copyright 2014 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="5"

CROS_WORKON_PROJECT="chromiumos/platform/chromiumos-assets"
CROS_WORKON_LOCALNAME="chromiumos-assets"
CROS_WORKON_OUTOFTREE_BUILD=1
CROS_WORKON_INCREMENTAL_BUILD=1

inherit cros-workon

DESCRIPTION="Chromium OS-specific assets"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/chromiumos-assets"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="~*"
IUSE=""

src_install() {
	insinto /usr/share/chromeos-assets/images
	doins -r images/*

	insinto /usr/share/chromeos-assets/images_100_percent
	doins -r images_100_percent/*

	insinto /usr/share/chromeos-assets/images_200_percent
	doins -r images_200_percent/*
}
