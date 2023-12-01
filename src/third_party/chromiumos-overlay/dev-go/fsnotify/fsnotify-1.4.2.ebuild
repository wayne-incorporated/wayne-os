# Copyright 2016 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/fsnotify/fsnotify v${PV}"

CROS_GO_PACKAGES=(
	"github.com/fsnotify/fsnotify"
)

inherit cros-go

DESCRIPTION="File system notifications for Go"
HOMEPAGE="https://github.com/fsnotify/fsnotify"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""

RESTRICT="binchecks strip"

DEPEND=""
RDEPEND="dev-go/go-sys"
