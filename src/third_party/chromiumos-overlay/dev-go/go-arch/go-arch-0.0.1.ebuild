# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="go.googlesource.com/arch:golang.org/x/arch cbf565b21d1e6f86b3114f28f516032b201c97fa"

CROS_GO_PACKAGES=(
	"golang.org/x/arch/arm/..."
	"golang.org/x/arch/arm64/..."
	"golang.org/x/arch/x86/..."
)

inherit cros-go

DESCRIPTION="Machine architecture information used by the Go toolchain."
HOMEPAGE="https://golang.org/x/arch"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="dev-go/rsc-io-pdf"
RDEPEND=""
