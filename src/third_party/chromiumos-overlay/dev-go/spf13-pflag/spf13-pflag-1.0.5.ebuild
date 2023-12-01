# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/spf13/pflag v${PV}"

CROS_GO_PACKAGES=(
	"github.com/spf13/pflag"
)

inherit cros-go

DESCRIPTION="pflag is a drop-in replacement for Go's flag package, implementing POSIX/GNU-style --flags.

pflag is compatible with the GNU extensions to the POSIX recommendations for command-line options."
HOMEPAGE="https://github.com/spf13/pflag"
SRC_URI="$(cros-go_src_uri)"

LICENSE="BSD-Google"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND=""
RDEPEND=""
