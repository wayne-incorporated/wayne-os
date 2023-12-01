# Copyright 2019 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/elastic/go-libaudit v${PV}"

CROS_GO_PACKAGES=(
	"github.com/elastic/go-libaudit"
	"github.com/elastic/go-libaudit/aucoalesce"
	"github.com/elastic/go-libaudit/auparse"
	"github.com/elastic/go-libaudit/rule"
)

inherit cros-go

DESCRIPTION="A Go library for communicating with the Linux Audit Framework."
HOMEPAGE="https://github.com/elastic/go-libaudit"
SRC_URI="$(cros-go_src_uri)"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE=""

RESTRICT="binchecks strip"

DEPEND="dev-go/yaml:0"
RDEPEND=""
