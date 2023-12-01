# Copyright 2020 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/abema/go-mp4 5bdb34118acfef5536b63c4b70ce4314b5373f87"

CROS_GO_PACKAGES=(
	"github.com/abema/go-mp4/..."
)

inherit cros-go

DESCRIPTION="Go library for reading and writing MP4 file"
HOMEPAGE="https://github.com/abema/go-mp4"
SRC_URI="$(cros-go_src_uri)"

LICENSE="MIT"
SLOT="0"
KEYWORDS="*"
IUSE=""
RESTRICT="binchecks strip"

DEPEND="
	dev-go/bufseekio
	dev-go/writeseeker
	dev-go/crypto
	dev-go/go-spew
	dev-go/uuid
	dev-go/testify
	dev-go/go-billy
	dev-go/yaml:0
"
RDEPEND="${DEPEND}"
