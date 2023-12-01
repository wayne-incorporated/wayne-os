# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7

CROS_GO_SOURCE="github.com/BurntSushi/toml v${PV}"

inherit cros-go

DESCRIPTION="TOML parser for Golang with reflection."
HOMEPAGE="https://github.com/BurntSushi/toml"
SRC_URI="$(cros-go_src_uri)"

CROS_GO_PACKAGES=(
	"github.com/BurntSushi/toml"
	"github.com/BurntSushi/toml/internal"
	"github.com/BurntSushi/toml/internal/tag"
)

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND=""
RDEPEND="${DEPEND}"
