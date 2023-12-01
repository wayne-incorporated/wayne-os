# Copyright 2018 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/opencontainers/selinux f5322ec9f783adb26f125d2086908dc546508b6d"

CROS_GO_PACKAGES=(
	"github.com/opencontainers/selinux/go-selinux"
)

CROS_GO_TEST=(
	"${CROS_GO_PACKAGES[@]}"
)

inherit cros-go

DESCRIPTION="common selinux implementation"
HOMEPAGE="https://github.com/opencontainers/selinux"
SRC_URI="$(cros-go_src_uri)"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="
	dev-go/errors
"
RDEPEND=""
