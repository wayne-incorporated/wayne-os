# Copyright 2021 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/mitchellh/go-wordwrap v${PV}"

CROS_GO_PACKAGES=(
	"github.com/mitchellh/go-wordwrap"
)

inherit cros-go

DESCRIPTION="A package for Go that automatically wraps words into multiple lines."
HOMEPAGE="https://github.com/mitchellh/go-wordwrap"
SRC_URI="$(cros-go_src_uri)"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE=""

DEPEND="
"
RDEPEND="${DEPEND}"
