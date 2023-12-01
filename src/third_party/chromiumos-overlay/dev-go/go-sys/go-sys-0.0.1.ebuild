# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="go.googlesource.com/sys:golang.org/x/sys 04245dca01dae530ad36275d662a90d6b8a5ee29"

CROS_GO_PACKAGES=(
	"golang.org/x/sys/cpu"
	"golang.org/x/sys/execabs"
	"golang.org/x/sys/internal/unsafeheader"
	"golang.org/x/sys/unix"
)

CROS_GO_TEST=(
	"golang.org/x/sys/unix"
)

inherit cros-go

DESCRIPTION="Go packages for low-level interaction with the operating system"
HOMEPAGE="https://golang.org/x/sys"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND=""
RDEPEND=""
