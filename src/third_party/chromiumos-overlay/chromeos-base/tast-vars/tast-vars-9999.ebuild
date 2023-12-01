# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

inherit cros-constants

CROS_WORKON_REPO="${CROS_GIT_HOST_URL}"
CROS_WORKON_PROJECT="chromiumos/platform/tast-tests"
CROS_WORKON_LOCALNAME="platform/tast-tests"
CROS_WORKON_SUBTREE="vars"
inherit cros-workon

DESCRIPTION="All Tast static variables"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="~*"
IUSE=""

RDEPEND="virtual/tast-vars"
DEPEND="${RDEPEND}"

src_install() {
	insinto /etc/tast/vars/public
	doins -r vars/*
}
