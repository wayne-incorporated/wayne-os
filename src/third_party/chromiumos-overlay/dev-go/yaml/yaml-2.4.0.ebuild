# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/go-yaml/yaml:gopkg.in/yaml.v2 v${PV}"

CROS_GO_PACKAGES=(
	"gopkg.in/yaml.v2"
)

inherit cros-go

DESCRIPTION="YAML support for the Go language"
HOMEPAGE="https://gopkg.in/yaml.v2"
SRC_URI="$(cros-go_src_uri)"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE="test"
RESTRICT="binchecks strip"

DEPEND="dev-go/check"
RDEPEND=""
