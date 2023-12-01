# Copyright 2022 The ChromiumOS Authors
# Distributed under the terms of the GNU General Public License v2.

EAPI=7

CROS_GO_SOURCE="github.com/docker/distribution:github.com/docker/distribution/v2 v${PV}"

PATCHES=(
	"${FILESDIR}"/distribution-2.7.1-add-distribution-major-ver.patch
)

CROS_GO_PACKAGES=(
	"github.com/docker/distribution/v2/digestset"
	"github.com/docker/distribution/v2/reference"
	"github.com/docker/distribution/v2/registry/api/errcode"
)

inherit cros-go

DESCRIPTION="The toolkit to pack, ship, store, and deliver container content"
HOMEPAGE="https://github.com/docker/distribution"
SRC_URI="$(cros-go_src_uri)"

LICENSE="Apache-2.0"
SLOT="0"
KEYWORDS="*"
IUSE="test"
RESTRICT="binchecks strip"
DEPEND=""
RDEPEND="!<=dev-go/docker-20.10.8-r1"
