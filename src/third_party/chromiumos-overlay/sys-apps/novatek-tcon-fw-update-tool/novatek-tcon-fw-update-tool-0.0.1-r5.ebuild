# Copyright 2019 The ChromiumOS Authors
# This file distributed under the terms of the BSD license.

EAPI="6"

CROS_WORKON_COMMIT="a78b7b0ba128471af835e44dc97698d39fd89bbf"
CROS_WORKON_TREE="9749e461e4770cfb2e627ae2960239a3e8599e22"
CROS_WORKON_PROJECT="chromiumos/third_party/novatek-tcon-fw-update-tool"
CROS_WORKON_LOCALNAME="novatek-tcon-fw-update-tool"

inherit cros-common.mk cros-workon

DESCRIPTION="Novatek TCON Firmware Updater"
HOMEPAGE="https://chromium.googlesource.com/chromiumos/third_party/novatek-tcon-fw-update-tool/"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"

src_install() {
	dosbin "${OUT}"/nvt-tcon-fw-updater
}
