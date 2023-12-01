# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/mdlayher/kobject b96c97ecd94cb099c51321f651acb576067c960c"

CROS_GO_PACKAGES=(
	"github.com/mdlayher/kobject"
)

inherit cros-go

DESCRIPTION="Package kobject provides access to Linux kobject userspace events"
HOMEPAGE="https://github.com/mdlayher/kobject"
SRC_URI="$(cros-go_src_uri)"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE=""

RESTRICT="binchecks strip"

DEPEND="
	dev-go/cmp
	dev-go/go-sys
	dev-go/netlink
"
RDEPEND=""
