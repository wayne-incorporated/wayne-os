# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/cpuguy83/go-md2man:github.com/cpuguy83/go-md2man/v2 v${PV}"

CROS_GO_PACKAGES=(
	"github.com/cpuguy83/go-md2man/v2"
	"github.com/cpuguy83/go-md2man/v2/md2man"
)

CROS_GO_BINARIES=(
	"github.com/cpuguy83/go-md2man/v2:/usr/bin/go-md2man"
)

inherit cros-go

DESCRIPTION="Converts markdown into roff (man pages)."
HOMEPAGE="https://github.com/cpuguy83/go-md2man"
SRC_URI="$(cros-go_src_uri)"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE="test"
RESTRICT="binchecks"
DEPEND="
	dev-go/blackfriday
"
