# Copyright 2017 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/shirou/gopsutil:github.com/shirou/gopsutil/v3 v${PV}"

CROS_GO_PACKAGES=(
	"github.com/shirou/gopsutil/v3/..."
)

CROS_GO_TEST=(
	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil//v3disk"
	# host fails due to missing /var/run/utmp in chroot.
	"github.com/shirou/gopsutil/v3/internal/..."
	"github.com/shirou/gopsutil/v3/load"
	# mem, net, and process require github.com/stretchr/testify/assert.
)

inherit cros-go

DESCRIPTION="Cross-platform lib for process and system monitoring in Go"
HOMEPAGE="https://github.com/shirou/gopsutil"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD"
SLOT="0"
KEYWORDS="*"
IUSE="test"
RESTRICT="binchecks strip"

DEPEND="
	dev-go/cmp
	dev-go/errcheck
	dev-go/go-sys
	dev-go/go-sysconf
	dev-go/testify
"
RDEPEND="${DEPEND}"
