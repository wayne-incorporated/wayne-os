# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI="7"

CROS_WORKON_PROJECT="chromiumos/platform/microbenchmarks"
CROS_WORKON_LOCALNAME="../platform/microbenchmarks"

inherit cros-workon cros-common.mk cros-sanitizers

DESCRIPTION="Home for microbenchmarks designed in-house."
HOMEPAGE="https://chromium.googlesource.com/chromiumos/platform/microbenchmarks"

LICENSE="BSD-Google"
KEYWORDS="~*"

src_configure() {
	sanitizers-setup-env
	default
}

src_install() {
	dobin "${OUT}"/memory-eater/memory-eater
}
