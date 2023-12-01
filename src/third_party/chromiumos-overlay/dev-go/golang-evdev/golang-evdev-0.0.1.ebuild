# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_GO_SOURCE="github.com/gvalkov/golang-evdev 287e62b94bcb850ab42e711bd74b2875da83af2c"

CROS_GO_PACKAGES=(
	"github.com/gvalkov/golang-evdev"
)

inherit cros-go

DESCRIPTION="Provides Go language bindings to the generic input event interface in Linux."
HOMEPAGE="https://github.com/gvalkov/golang-evdev"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="sys-kernel/linux-headers:="
RDEPEND=""
