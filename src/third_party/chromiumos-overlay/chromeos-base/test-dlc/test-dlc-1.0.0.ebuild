# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=6

DESCRIPTION="A test Downloadable Content (DLC) module for DLC tast tests"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform2/+/master/dlcservice"
SRC_URI=""

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE="dlc"
REQUIRED_USE="dlc"

src_unpack() {
	# Makes emerge pass.
	S="${WORKDIR}"
}

src_install() {
	insinto "/opt/google/dlc"
	doins -r "${FILESDIR}/rootfs_meta"/*
	insinto "/usr/local/dlc"
	doins -r "${FILESDIR}/payloads"/*
	insinto "/usr/local/dlc"
	doins -r "${FILESDIR}/images"/*
}
