# Copyright 2011 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
CROS_WORKON_COMMIT="5951466339783dcb18efcd6f1d31a54dc45fd188"
CROS_WORKON_TREE="12673839517f6b85e554d67f6042bbd4fd5b7ebf"
CROS_WORKON_PROJECT="chromiumos/platform/crostestutils"
CROS_WORKON_LOCALNAME="platform/crostestutils"
CROS_WORKON_SUBTREE="recover_duts"

inherit cros-workon

DESCRIPTION="Test tool that recovers bricked Chromium OS test devices"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/crostestutils/+/master/recover_duts/"

LICENSE="BSD-Google"
SLOT="0/0"
KEYWORDS="*"

RDEPEND="
	chromeos-base/chromeos-init
"

DEPEND=""

src_unpack() {
	cros-workon_src_unpack
	S+="/recover_duts"
}

src_install() {
	dosbin reload_network_device

	exeinto /usr/libexec/recover-duts
	newexe recover_duts.sh recover_duts

	exeinto /usr/libexec/recover-duts/hooks
	doexe hooks/*
}
