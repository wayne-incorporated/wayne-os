# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/go-yaml/yaml:gopkg.in/yaml.v3 496545a6307b2a7d7a710fd516e5e16e8ab62dbc"

CROS_GO_PACKAGES=(
	"gopkg.in/yaml.v3"
)

inherit cros-go

DESCRIPTION="YAML support for the Go language"
HOMEPAGE="https://gopkg.in/yaml.v3"
SRC_URI="$(cros-go_src_uri)"

LICENSE="Apache-2.0"
SLOT="3"
KEYWORDS="*"
IUSE="test"
RESTRICT="binchecks strip"

DEPEND="dev-go/check"
RDEPEND=""
